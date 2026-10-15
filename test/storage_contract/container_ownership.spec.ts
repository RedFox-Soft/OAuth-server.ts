import { describe, it, expect, beforeEach } from 'bun:test';

import { ContainerOwnershipStore } from 'lib/adapters/memory/containerOwnershipStore.ts';
import { UserBucketStore } from 'lib/adapters/memory/userBucketStore.ts';

/*
 * Memory implementation only, for the reason every store spec here gives: the database backends connect at
 * module scope. Their halves are exercised by database/verify_mongodb.ts and database/verify_postgres.ts.
 */

let buckets: UserBucketStore;
let ownership: ContainerOwnershipStore;

async function ownerOf(id: string) {
	return (await buckets.find(id))?.ownerGroupId;
}

/**
 * @proves A bucket changes group only from the group the mover saw it in: a move from any other group
 * changes nothing, and of two moves racing from the same group exactly one takes effect.
 */
describe('moving a bucket to another group', () => {
	beforeEach(() => {
		buckets = new UserBucketStore();
		ownership = new ContainerOwnershipStore({ buckets });
	});

	it('moves a bucket that is in the group it is moved from', async () => {
		const bucket = await buckets.create({ name: 'b', ownerGroupId: 'src' });

		const result = await ownership.moveBucket(bucket._id, 'src', 'dst');

		expect(result).toEqual({ status: 'moved' });
		expect(await ownerOf(bucket._id)).toBe('dst');
	});

	it('changes nothing when the bucket belongs to a third group', async () => {
		const bucket = await buckets.create({ name: 'b', ownerGroupId: 'third' });

		const result = await ownership.moveBucket(bucket._id, 'src', 'dst');

		expect(result).toEqual({ status: 'conflict' });
		expect(await ownerOf(bucket._id)).toBe('third');
	});

	/* A bucket already where the mover wanted it was moved by somebody else, whose move is not this one. */
	it('reports a conflict for a bucket already in the destination group', async () => {
		const bucket = await buckets.create({ name: 'b', ownerGroupId: 'dst' });

		const result = await ownership.moveBucket(bucket._id, 'src', 'dst');

		expect(result).toEqual({ status: 'conflict' });
		expect(await ownerOf(bucket._id)).toBe('dst');
	});

	it('reports a conflict for a bucket that does not exist', async () => {
		expect(await ownership.moveBucket('no-such-bucket', 'src', 'dst')).toEqual({
			status: 'conflict'
		});
	});

	/*
	 * Two administrators moving the same bucket from the same group at once: one move wins, and the other is
	 * told so rather than silently overwriting it.
	 */
	it('lets exactly one of two concurrent moves from the same group take effect', async () => {
		const bucket = await buckets.create({ name: 'b', ownerGroupId: 'src' });

		const results = await Promise.all([
			ownership.moveBucket(bucket._id, 'src', 'first'),
			ownership.moveBucket(bucket._id, 'src', 'second')
		]);

		expect(results.map((r) => r.status).sort()).toEqual(['conflict', 'moved']);
		const winner = results[0].status === 'moved' ? 'first' : 'second';
		expect(await ownerOf(bucket._id)).toBe(winner);
	});

	it('leaves other buckets where they are', async () => {
		const moved = await buckets.create({ name: 'a', ownerGroupId: 'src' });
		const other = await buckets.create({ name: 'b', ownerGroupId: 'src' });

		await ownership.moveBucket(moved._id, 'src', 'dst');

		expect(await ownerOf(other._id)).toBe('src');
	});
});
