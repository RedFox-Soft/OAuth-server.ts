import type {
	ContainerMoveResult,
	ContainerOwnershipStoreInstance,
	UserBucketStoreInstance
} from '../types.js';

/*
 * The memory store hands out its live records, and its update assigns when called. So of two moves racing
 * for one bucket, the second to resume reads the first one's write on the same live record and conflicts —
 * the conditional write the database backends perform.
 */
export class ContainerOwnershipStore implements ContainerOwnershipStoreInstance {
	private buckets: UserBucketStoreInstance;

	constructor(stores: { buckets: UserBucketStoreInstance }) {
		this.buckets = stores.buckets;
	}

	async moveBucket(
		bucketId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		const bucket = await this.buckets.find(bucketId);
		if (!bucket || bucket.ownerGroupId !== from) {
			return { status: 'conflict' };
		}
		await this.buckets.update(bucketId, { ownerGroupId: to });
		return { status: 'moved' };
	}
}
