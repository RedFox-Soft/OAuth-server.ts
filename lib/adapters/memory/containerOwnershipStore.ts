import type {
	ContainerMoveResult,
	ContainerOwnershipStoreInstance,
	ProjectStoreInstance,
	UserBucketStoreInstance
} from '../types.js';

/*
 * The memory stores hand out their live records, so the move reads them, checks them and writes them with
 * no `await` between the check and the last write. On a single-threaded runtime that is what makes this
 * atomic; with an await in between it would pass every test and lose the race the database backends are
 * required to win (Principle III).
 */
export class ContainerOwnershipStore implements ContainerOwnershipStoreInstance {
	private buckets: UserBucketStoreInstance;
	private projects: ProjectStoreInstance;

	constructor(stores: {
		buckets: UserBucketStoreInstance;
		projects: ProjectStoreInstance;
	}) {
		this.buckets = stores.buckets;
		this.projects = stores.projects;
	}

	async moveBucket(
		bucketId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		// One await for both reads: neither method awaits inside, so both see the same instant.
		const [bucket, all] = await Promise.all([
			this.buckets.find(bucketId),
			this.projects.list()
		]);
		const either = (owner: string) => owner === from || owner === to;
		const bound = all.filter((p) => p.bucketId === bucketId);
		if (
			!bucket ||
			!either(bucket.ownerGroupId) ||
			!bound.every((p) => either(p.ownerGroupId))
		) {
			return { status: 'conflict' };
		}
		const moving = bound.filter((p) => p.ownerGroupId === from);
		// Each update assigns synchronously when called; awaiting them together keeps the writes adjacent.
		await Promise.all([
			this.buckets.update(bucketId, { ownerGroupId: to }),
			...moving.map((p) => this.projects.update(p._id, { ownerGroupId: to }))
		]);
		return { status: 'moved', projectIds: moving.map((p) => p._id) };
	}

	async moveProject(
		projectId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		const project = await this.projects.find(projectId);
		if (
			!project ||
			project.ownerGroupId !== from ||
			project.bucketId !== null
		) {
			return { status: 'conflict' };
		}
		await this.projects.update(projectId, { ownerGroupId: to });
		return { status: 'moved', projectIds: [projectId] };
	}
}
