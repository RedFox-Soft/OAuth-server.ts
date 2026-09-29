import type {
	BucketKey,
	BucketKeyState,
	BucketKeysStoreInstance
} from '../types.js';

/*
 * In-memory bucket keys. `createIfAbsent` is a synchronous check-and-set, which is atomic here because
 * nothing interleaves inside it; the datastores get the same guarantee from their primary key.
 */
export class BucketKeysStore implements BucketKeysStoreInstance {
	private keys = new Map<string, BucketKey>();

	async listByBucket(bucketId: string): Promise<BucketKey[]> {
		return [...this.keys.values()]
			.filter((key) => key.bucketId === bucketId)
			.map((key) => structuredClone(key));
	}

	async find(bucketId: string, kid: string): Promise<BucketKey | null> {
		const found = [...this.keys.values()].find(
			(key) => key.bucketId === bucketId && key.kid === kid
		);
		return found ? structuredClone(found) : null;
	}

	async createIfAbsent(key: BucketKey): Promise<boolean> {
		if (this.keys.has(key._id)) return false;
		this.keys.set(key._id, structuredClone(key));
		return true;
	}

	async setState(
		bucketId: string,
		kid: string,
		state: BucketKeyState,
		at: Date
	): Promise<BucketKey | null> {
		for (const key of this.keys.values()) {
			if (key.bucketId === bucketId && key.kid === kid) {
				key.state = state;
				key.stateChangedAt = at;
				return structuredClone(key);
			}
		}
		return null;
	}

	async destroy(bucketId: string, kid: string): Promise<void> {
		for (const [id, key] of this.keys) {
			if (key.bucketId === bucketId && key.kid === kid) this.keys.delete(id);
		}
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		let removed = 0;
		for (const [id, key] of this.keys) {
			if (key.bucketId === bucketId) {
				this.keys.delete(id);
				removed += 1;
			}
		}
		return removed;
	}
}
