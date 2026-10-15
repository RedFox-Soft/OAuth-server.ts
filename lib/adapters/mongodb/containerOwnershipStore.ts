import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	ContainerMoveResult,
	ContainerOwnershipStoreInstance,
	UserBucket
} from '../types.js';

/*
 * One conditional write: of two moves racing for one bucket, only one finds it still in the group it may
 * move from. Nothing else is written — what the bucket holds belongs to it by reference (specs/099).
 */
export class ContainerOwnershipStore implements ContainerOwnershipStoreInstance {
	private buckets = db.collection<UserBucket>(STORE_AREAS.userBuckets);

	async moveBucket(
		bucketId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		const result = await this.buckets.updateOne(
			{ _id: bucketId, ownerGroupId: from },
			{ $set: { ownerGroupId: to, updatedAt: new Date() } }
		);
		return result.matchedCount === 0
			? { status: 'conflict' }
			: { status: 'moved' };
	}
}
