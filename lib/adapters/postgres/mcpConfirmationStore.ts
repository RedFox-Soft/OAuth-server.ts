import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type {
	McpConfirmation,
	McpConfirmationStoreInstance
} from '../types.js';
import nanoid from '../../helpers/nanoid.js';

/* The record's own date fields, named rather than sniffed — a jsonb round trip returns them as
 * strings, and `record.expiresAt.getTime()` below is exactly the call that would fail. */
const DATE_FIELDS = ['createdAt', 'expiresAt'] as const;

export class McpConfirmationStore implements McpConfirmationStoreInstance {
	private area: string = STORE_AREAS.mcpConfirmation;

	async issue(
		data: Omit<McpConfirmation, '_id' | 'createdAt' | 'expiresAt'> & {
			ttlSeconds: number;
		}
	): Promise<McpConfirmation> {
		const { ttlSeconds, ...rest } = data;
		const now = new Date();
		const record: McpConfirmation = {
			_id: nanoid(),
			...rest,
			createdAt: now,
			expiresAt: new Date(now.getTime() + ttlSeconds * 1000)
		};

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${record._id}, ${record}, ${record.expiresAt})
		`;

		/* The freshly built record, not a read-back: it already holds real Dates, and returning it
		 * keeps the caller's value identical on both backends without a revive step. */
		return record;
	}

	/*
	 * `DELETE ... RETURNING`, not select-then-delete: single use has to hold under concurrency, and two
	 * agents redeeming the same token simultaneously must not both proceed. One statement is what makes
	 * that true rather than likely — the same property MongoDB gets from `findOneAndDelete`.
	 *
	 * An expired record is reported as absent. The check cannot be left to the sweeper, which runs on
	 * its own schedule and may be up to a minute behind, exactly as MongoDB's TTL monitor is.
	 */
	async redeem(id: string): Promise<McpConfirmation | null> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE id = ${id} RETURNING doc
		`;

		const stored = docOf<McpConfirmation>(rows[0]);
		if (stored === undefined) return null;

		const record = reviveDates(stored, DATE_FIELDS);
		if (record.expiresAt.getTime() <= Date.now()) return null;
		return record;
	}

	async count(): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS pending FROM ${handle(this.area)}
			WHERE expires_at > now()
		`;
		return Number((rows[0] as { pending?: number } | undefined)?.pending ?? 0);
	}
}
