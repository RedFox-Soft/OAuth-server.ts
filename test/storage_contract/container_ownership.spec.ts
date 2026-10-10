import { describe, it, expect, beforeEach } from 'bun:test';

import { ContainerOwnershipStore } from 'lib/adapters/memory/containerOwnershipStore.ts';
import { ProjectStore } from 'lib/adapters/memory/projectStore.ts';
import { UserBucketStore } from 'lib/adapters/memory/userBucketStore.ts';

/*
 * Memory implementation only, for the reason every store spec here gives: the database backends connect at
 * module scope. Their halves are exercised by database/verify_mongodb.ts and database/verify_postgres.ts.
 */

let buckets: UserBucketStore;
let projects: ProjectStore;
let ownership: ContainerOwnershipStore;

async function ownerOf(kind: 'bucket' | 'project', id: string) {
	const record =
		kind === 'bucket' ? await buckets.find(id) : await projects.find(id);
	return record?.ownerGroupId;
}

/**
 * @proves A container changes group only as a whole: a bucket and every project using it move together or
 * not at all, a move left half-done completes when repeated, and a project using a bucket never moves alone.
 */
describe('moving a container to another group', () => {
	beforeEach(() => {
		buckets = new UserBucketStore();
		projects = new ProjectStore();
		ownership = new ContainerOwnershipStore({ buckets, projects });
	});

	async function bucketWith(owner: string, projectOwners: string[]) {
		const bucket = await buckets.create({ name: 'b', ownerGroupId: owner });
		const bound = [];
		for (const [i, projectOwner] of projectOwners.entries()) {
			bound.push(
				await projects.create({
					name: `p${i}`,
					slug: `p${i}-${bucket._id}`,
					ownerGroupId: projectOwner,
					bucketId: bucket._id
				})
			);
		}
		return { bucket, bound };
	}

	it('moves a bucket and every project using it', async () => {
		const { bucket, bound } = await bucketWith('src', ['src', 'src']);

		const result = await ownership.moveBucket(bucket._id, 'src', 'dst');

		expect(result).toEqual({
			status: 'moved',
			projectIds: bound.map((p) => p._id)
		});
		expect(await ownerOf('bucket', bucket._id)).toBe('dst');
		for (const p of bound) expect(await ownerOf('project', p._id)).toBe('dst');
	});

	it('changes nothing when one of the bucket’s projects belongs to a third group', async () => {
		const { bucket, bound } = await bucketWith('src', ['src', 'third']);

		expect((await ownership.moveBucket(bucket._id, 'src', 'dst')).status).toBe(
			'conflict'
		);
		expect(await ownerOf('bucket', bucket._id)).toBe('src');
		expect(await ownerOf('project', bound[0]?._id ?? '')).toBe('src');
	});

	it('changes nothing when the bucket belongs to a third group', async () => {
		const { bucket, bound } = await bucketWith('third', ['src']);

		expect((await ownership.moveBucket(bucket._id, 'src', 'dst')).status).toBe(
			'conflict'
		);
		expect(await ownerOf('bucket', bucket._id)).toBe('third');
		expect(await ownerOf('project', bound[0]?._id ?? '')).toBe('src');
	});

	it('moves the remaining projects of a move that stopped after the bucket', async () => {
		const { bucket, bound } = await bucketWith('dst', ['dst', 'src']);

		const result = await ownership.moveBucket(bucket._id, 'src', 'dst');

		expect(result).toEqual({
			status: 'moved',
			projectIds: [bound[1]?._id ?? '']
		});
		for (const p of bound) expect(await ownerOf('project', p._id)).toBe('dst');
	});

	it('leaves projects of other buckets where they are', async () => {
		const { bucket } = await bucketWith('src', ['src']);
		const { bound: elsewhere } = await bucketWith('src', ['src']);

		await ownership.moveBucket(bucket._id, 'src', 'dst');

		expect(await ownerOf('project', elsewhere[0]?._id ?? '')).toBe('src');
	});

	it('moves a project that uses no bucket', async () => {
		const project = await projects.create({
			name: 'solo',
			slug: 'solo',
			ownerGroupId: 'src'
		});

		expect(
			(await ownership.moveProject(project._id, 'src', 'dst')).status
		).toBe('moved');
		expect(await ownerOf('project', project._id)).toBe('dst');
	});

	it('changes nothing for a project once it uses a bucket', async () => {
		const { bound } = await bucketWith('src', ['src']);
		const id = bound[0]?._id ?? '';

		expect((await ownership.moveProject(id, 'src', 'dst')).status).toBe(
			'conflict'
		);
		expect(await ownerOf('project', id)).toBe('src');
	});

	it('changes nothing for a project no longer in the group it is moved from', async () => {
		const project = await projects.create({
			name: 'solo',
			slug: 'solo-2',
			ownerGroupId: 'elsewhere'
		});

		expect(
			(await ownership.moveProject(project._id, 'src', 'dst')).status
		).toBe('conflict');
		expect(await ownerOf('project', project._id)).toBe('elsewhere');
	});
});
