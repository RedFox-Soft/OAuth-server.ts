import { sql } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	ContainerMoveResult,
	ContainerOwnershipStoreInstance
} from '../types.js';

/*
 * One conditional write: of two moves racing for one bucket, only one finds it still in the group it may
 * move from. Nothing else is written — what the bucket holds belongs to it by reference (specs/099).
 */
export class ContainerOwnershipStore implements ContainerOwnershipStoreInstance {
	private bucketArea: string = STORE_AREAS.userBuckets;

	async moveBucket(
		bucketId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		const handle = sql();
		const patch = { ownerGroupId: to, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.bucketArea)} SET doc = doc || ${patch}
			WHERE id = ${bucketId} AND doc->>'ownerGroupId' = ${from}
			RETURNING id
		`;
		return rows.length === 0 ? { status: 'conflict' } : { status: 'moved' };
	}
}
