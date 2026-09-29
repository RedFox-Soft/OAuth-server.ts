import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	BucketKey,
	type BucketKeyState,
	type BucketKeysStoreInstance
} from '../types.js';

export class BucketKeysStore implements BucketKeysStoreInstance {
	private area: string = STORE_AREAS.bucketKeys;

	async listByBucket(bucketId: string): Promise<BucketKey[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
		`;
		return rows.map((row: unknown) => this.keyOf(row));
	}

	async find(bucketId: string, kid: string): Promise<BucketKey | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'kid' = ${kid}
		`;
		return rows[0] ? this.keyOf(rows[0]) : null;
	}

	/* `ON CONFLICT DO NOTHING` on the primary key, and the returned row says who won. */
	async createIfAbsent(key: BucketKey): Promise<boolean> {
		const handle = sql();
		const rows = await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${key._id}, ${key}, NULL)
			ON CONFLICT (id) DO NOTHING
			RETURNING id
		`;
		return rows.length === 1;
	}

	async setState(
		bucketId: string,
		kid: string,
		state: BucketKeyState,
		at: Date
	): Promise<BucketKey | null> {
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${{ state, stateChangedAt: at }}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'kid' = ${kid}
			RETURNING doc
		`;
		return rows[0] ? this.keyOf(rows[0]) : null;
	}

	async destroy(bucketId: string, kid: string): Promise<void> {
		const handle = sql();
		await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'kid' = ${kid}
		`;
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING id
		`;
		return rows.length;
	}

	private keyOf(row: unknown): BucketKey {
		return documentOf(this.area, BucketKey, docOf(row));
	}
}
