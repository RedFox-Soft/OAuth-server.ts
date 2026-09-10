import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type { AdminSession, AdminSessionStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

/* Three dates, and all three are compared numerically below — a jsonb round trip returns them as
 * strings, so reviving them is what keeps those comparisons meaningful rather than always false. */
const DATE_FIELDS = ['createdAt', 'expiresAt', 'absoluteExpiresAt'] as const;

export class AdminSessionStore implements AdminSessionStoreInstance {
	private area: string = STORE_AREAS.adminSession;

	async create(data: {
		userId: string;
		bucketId: string;
		activeGroupId: string;
		tokens: AdminSession['tokens'];
		ttlSeconds: number;
		absoluteTtlSeconds: number;
	}): Promise<AdminSession> {
		const now = new Date();
		const session: AdminSession = {
			_id: nanoid(),
			userId: data.userId,
			bucketId: data.bucketId,
			activeGroupId: data.activeGroupId,
			tokens: data.tokens,
			createdAt: now,
			expiresAt: new Date(now.getTime() + data.ttlSeconds * 1000),
			absoluteExpiresAt: new Date(
				now.getTime() + data.absoluteTtlSeconds * 1000
			)
		};

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${session._id}, ${session}, ${session.expiresAt})
		`;

		return session;
	}

	/*
	 * Two expiries, and both are load-bearing: the sliding one a request refreshes, and the absolute
	 * one it cannot. An expired session is deleted on the way out rather than left for the sweeper,
	 * which runs on its own schedule — the same reason the MongoDB store does not leave it to the TTL
	 * monitor.
	 */
	async find(id: string): Promise<AdminSession | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		const stored = docOf<AdminSession>(rows[0]);
		if (stored === undefined) return null;

		const session = reviveDates(stored, DATE_FIELDS);
		const now = Date.now();
		if (
			session.expiresAt.getTime() <= now ||
			session.absoluteExpiresAt.getTime() <= now
		) {
			await this.destroy(id);
			return null;
		}
		return session;
	}

	/*
	 * The sliding expiry, clamped to the absolute one — a session cannot be extended past the ceiling
	 * however often it is used.
	 *
	 * The clamp is computed in SQL rather than read-then-written, so two concurrent requests on one
	 * session cannot interleave and set an expiry neither of them decided. Both the document field and
	 * the `expires_at` column move together; the column is what the sweeper reads, the field is what
	 * `find` reads, and letting them drift would make a session outlive its own record.
	 */
	async touch(id: string, ttlSeconds: number): Promise<void> {
		const handle = sql();
		const next = new Date(Date.now() + ttlSeconds * 1000);

		await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(
					doc,
					'{expiresAt}',
					to_jsonb(LEAST(${next}::timestamptz, (doc->>'absoluteExpiresAt')::timestamptz))
				),
				expires_at = LEAST(${next}::timestamptz, (doc->>'absoluteExpiresAt')::timestamptz)
			WHERE id = ${id}
		`;
	}

	async setActiveGroup(id: string, groupId: string): Promise<void> {
		const handle = sql();
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(doc, '{activeGroupId}', to_jsonb(${groupId}::text))
			WHERE id = ${id}
		`;
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}
}
