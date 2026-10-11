import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { refusalId } from '../refusal_records.js';
import {
	ProvisioningRefusal,
	type ProvisioningRefusalInput,
	type ProvisioningRefusalPage,
	type ProvisioningRefusalStoreInstance
} from '../types.js';

/*
 * Refusals. `epoch` is compared as text because the index the inventory declares is over `doc->>'epoch'`;
 * `lastAt` is ordered as text, which is chronological because every value is written as an ISO-8601 UTC
 * string of the same length.
 */
export class ProvisioningRefusalStore implements ProvisioningRefusalStoreInstance {
	private area: string = STORE_AREAS.provisioningRefusals;

	/*
	 * One statement, atomic on the server: the insert writes the record the first time, and on conflict the
	 * update counts the attempt and replaces the operation. `lastAt` only moves forward, so notes landing out
	 * of order leave the latest. The document is passed as an object, never `JSON.stringify(...)`
	 * (lib/adapters/postgres/json.ts).
	 */
	async note(input: ProvisioningRefusalInput): Promise<void> {
		const record: ProvisioningRefusal = {
			_id: refusalId(input.connectionId, input.epoch, input.userId),
			connectionId: input.connectionId,
			bucketId: input.bucketId,
			epoch: input.epoch,
			userId: input.userId,
			operation: input.operation,
			firstAt: input.at,
			lastAt: input.at,
			attempts: 1
		};
		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} AS refusal (id, doc, expires_at)
			VALUES (${record._id}, ${record}, NULL)
			ON CONFLICT (id) DO UPDATE
			SET doc = (refusal.doc || ${{ operation: input.operation }})
				|| jsonb_build_object(
					'attempts', COALESCE((refusal.doc->>'attempts')::int, 0) + 1,
					'lastAt', GREATEST(refusal.doc->>'lastAt', EXCLUDED.doc->>'lastAt')
				)
		`;
	}

	async list(
		connectionId: string,
		epoch: number,
		limit: number
	): Promise<ProvisioningRefusalPage> {
		const handle = sql();
		const generation = () =>
			handle`doc->>'connectionId' = ${connectionId} AND doc->>'epoch' = ${String(epoch)}`;
		const [rows, counted] = await Promise.all([
			handle`
				SELECT doc FROM ${handle(this.area)}
				WHERE ${generation()}
				ORDER BY doc->>'lastAt' DESC
				LIMIT ${limit}
			`,
			handle<{ total: number }[]>`
				SELECT count(*)::int AS total FROM ${handle(this.area)} WHERE ${generation()}
			`
		]);
		return {
			refusals: rows.map((row: unknown) =>
				documentOf(this.area, ProvisioningRefusal, docOf(row))
			),
			total: counted[0]?.total ?? 0
		};
	}

	async destroyByConnection(connectionId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'connectionId' = ${connectionId}
			RETURNING id
		`;
		return rows.length;
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING id
		`;
		return rows.length;
	}
}
