import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	BucketKey,
	type BucketKeyState,
	type BucketKeysStoreInstance
} from '../types.js';

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

function keyOf(found: unknown): BucketKey {
	return documentOf(STORE_AREAS.bucketKeys, BucketKey, found);
}

export class BucketKeysStore implements BucketKeysStoreInstance {
	private collection = db.collection<BucketKey>(STORE_AREAS.bucketKeys);

	async listByBucket(bucketId: string): Promise<BucketKey[]> {
		return (await this.collection.find({ bucketId }).toArray()).map(keyOf);
	}

	async find(bucketId: string, kid: string): Promise<BucketKey | null> {
		const found = await this.collection.findOne({ bucketId, kid });
		return found ? keyOf(found) : null;
	}

	/* The primary key refuses a second insert of one `_id`, which is the whole of the guarantee. */
	async createIfAbsent(key: BucketKey): Promise<boolean> {
		try {
			await this.collection.insertOne(key, ABSENT_UNDEFINED);
			return true;
		} catch (error) {
			if (isDuplicateKey(error)) return false;
			throw error;
		}
	}

	async setState(
		bucketId: string,
		kid: string,
		state: BucketKeyState,
		at: Date
	): Promise<BucketKey | null> {
		const updated = await this.collection.findOneAndUpdate(
			{ bucketId, kid },
			{ $set: { state, stateChangedAt: at } },
			{ returnDocument: 'after' }
		);
		return updated ? keyOf(updated) : null;
	}

	async destroy(bucketId: string, kid: string): Promise<void> {
		await this.collection.deleteOne({ bucketId, kid });
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		return (await this.collection.deleteMany({ bucketId })).deletedCount;
	}
}
