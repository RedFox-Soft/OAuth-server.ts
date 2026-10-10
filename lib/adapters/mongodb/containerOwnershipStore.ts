import type { ClientSession } from 'mongodb';
import { client, db, supportsTransactions } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	ContainerMoveResult,
	ContainerOwnershipStoreInstance,
	Project,
	UserBucket
} from '../types.js';

/*
 * Moves a container between administrator groups. A transaction where the deployment has one (a replica
 * set or a sharded cluster); on a standalone `mongod`, ordered conditional writes — the bucket first, then
 * its projects — which is the declared `container-move-atomicity` divergence.
 *
 * Bucket first because its conditional write is the lock: of two moves racing for one bucket, only one
 * finds it still in a group it may move from, and the other writes nothing. A failure after it leaves the
 * bucket moved and some projects not, which a repeated move completes, since the bucket's own condition
 * admits `to`.
 */
export class ContainerOwnershipStore implements ContainerOwnershipStoreInstance {
	private buckets = db.collection<UserBucket>(STORE_AREAS.userBuckets);
	private projects = db.collection<Project>(STORE_AREAS.projects);

	private async atomically<T>(
		steps: (session?: ClientSession) => Promise<T>
	): Promise<T> {
		if (!(await supportsTransactions())) return steps();
		const session = client.startSession();
		try {
			let result: T | undefined;
			await session.withTransaction(async () => {
				result = await steps(session);
			});
			return result as T; // withTransaction resolves only after the callback assigned it
		} finally {
			await session.endSession();
		}
	}

	moveBucket(
		bucketId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		return this.atomically(async (session) => {
			const strays = await this.projects.countDocuments(
				{ bucketId, ownerGroupId: { $nin: [from, to] } },
				{ session }
			);
			if (strays > 0) return { status: 'conflict' };
			const updatedAt = new Date();
			const bucket = await this.buckets.updateOne(
				{ _id: bucketId, ownerGroupId: { $in: [from, to] } },
				{ $set: { ownerGroupId: to, updatedAt } },
				{ session }
			);
			if (bucket.matchedCount === 0) return { status: 'conflict' };
			const moving = await this.projects
				.find(
					{ bucketId, ownerGroupId: from },
					{ session, projection: { _id: 1 } }
				)
				.toArray();
			const projectIds = moving.map((p) => p._id);
			if (projectIds.length > 0) {
				await this.projects.updateMany(
					{ _id: { $in: projectIds }, ownerGroupId: from },
					{ $set: { ownerGroupId: to, updatedAt } },
					{ session }
				);
			}
			return { status: 'moved', projectIds };
		});
	}

	async moveProject(
		projectId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		const result = await this.projects.updateOne(
			{ _id: projectId, ownerGroupId: from, bucketId: null },
			{ $set: { ownerGroupId: to, updatedAt: new Date() } }
		);
		return result.matchedCount === 0
			? { status: 'conflict' }
			: { status: 'moved', projectIds: [projectId] };
	}
}
