import { sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { entriesOf } from '../../helpers/_/object.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import {
	BehindProxyApp,
	type BehindProxyAppPatch,
	type BehindProxyAppStoreInstance,
	type BehindProxyAppUsage
} from '../types.js';

const FIRST_TIMES = [
	'firstAskedAt',
	'firstSignInAt',
	'firstAllowedAt'
] as const;

/*
 * Apps behind a proxy. One address per bucket is the unique index on `(doc->>'bucketId', doc->>'address')` the
 * inventory declares, so a duplicate is a constraint violation refused even under a concurrent write — on the
 * INSERT and on the UPDATE that changes an address alike, with no `ON CONFLICT` and no read before either.
 */
export class BehindProxyAppStore implements BehindProxyAppStoreInstance {
	private area: string = STORE_AREAS.behindProxyApps;

	async listByBucket(bucketId: string): Promise<BehindProxyApp[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
		`;
		return rows
			.map((row: unknown) => this.recordOf(row))
			.filter(
				(record: BehindProxyApp | null): record is BehindProxyApp =>
					record !== null
			);
	}

	async find(id: string): Promise<BehindProxyApp | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.recordOf(rows[0]);
	}

	async create(record: BehindProxyApp): Promise<BehindProxyApp> {
		const handle = sql();
		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${record._id}, ${record}, NULL)
			`;
		} catch (error) {
			if (isUniqueViolation(error)) {
				throw new UniqueValueTaken('address', record.address);
			}
			throw error;
		}
		return record;
	}

	async update(
		id: string,
		patch: BehindProxyAppPatch
	): Promise<BehindProxyApp | null> {
		const set: Record<string, unknown> = { updatedAt: new Date() };
		for (const [field, value] of entriesOf(patch)) {
			if (value !== undefined) set[field] = value;
		}
		const handle = sql();
		try {
			const rows = await handle`
				UPDATE ${handle(this.area)} SET doc = doc || ${set}
				WHERE id = ${id}
				RETURNING doc
			`;
			return this.recordOf(rows[0]);
		} catch (error) {
			if (isUniqueViolation(error) && typeof patch.address === 'string') {
				throw new UniqueValueTaken('address', patch.address);
			}
			throw error;
		}
	}

	async delete(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	async destroyByBucket(bucketId: string): Promise<string[]> {
		const handle = sql();
		const rows = await handle<{ id: string }[]>`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING id
		`;
		return rows.map((row) => row.id);
	}

	/*
	 * One statement. The first times go under the stored document (`firsts || doc`), so a time already recorded
	 * wins and a missing one is written; `lastAskedAt` goes over it, so it always moves.
	 */
	async noteUsage(id: string, fields: BehindProxyAppUsage): Promise<void> {
		const firsts: Record<string, Date> = {};
		for (const field of FIRST_TIMES) {
			const at = fields[field];
			if (at) firsts[field] = at;
		}
		const last: Record<string, Date> = {};
		if (fields.lastAskedAt) last.lastAskedAt = fields.lastAskedAt;
		if (Object.keys(firsts).length + Object.keys(last).length === 0) return;
		const handle = sql();
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = (${firsts}::jsonb || doc) || ${last}::jsonb
			WHERE id = ${id}
		`;
	}

	private recordOf(row: unknown): BehindProxyApp | null {
		const doc = docOf(row);
		return doc === undefined
			? null
			: documentOf(this.area, BehindProxyApp, doc);
	}
}
