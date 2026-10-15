import type {
	AdminAuditStoreInstance,
	ContainerOwnershipStoreInstance,
	GroupStoreInstance,
	UserBucketStoreInstance
} from '../lib/adapters/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/*
 * Moving a bucket between administrator groups, and the upgrade that made personal groups personal
 * (specs/075), against a real datastore: what an in-memory double cannot show is whether the move is one
 * change under two concurrent requests, and whether the migration's raw writes read back through the stores.
 * Since specs/099 a bucket holds its applications and APIs by reference, so the move is one conditional write
 * of the bucket. Shared by verify_mongodb.ts and verify_postgres.ts so both backends answer the same
 * questions in the same words.
 */
export async function verifyContainerOwnership(
	stores: {
		buckets: UserBucketStoreInstance;
		ownership: ContainerOwnershipStoreInstance;
		audit: AdminAuditStoreInstance;
	},
	check: Check
): Promise<void> {
	const { buckets, ownership, audit } = stores;
	const stamp = Date.now();
	const src = `move-src-${stamp}`;
	const bucketIn = (owner: string) =>
		buckets.create({
			name: `move-${stamp}-${Math.random()}`,
			ownerGroupId: owner
		});
	const ownerOf = async (id: string) => (await buckets.find(id))?.ownerGroupId;

	const plain = await bucketIn(src);
	const moved = await ownership.moveBucket(plain._id, src, 'move-dst');
	check(
		'a bucket move changes the group of a bucket in the group it leaves',
		moved.status === 'moved' && (await ownerOf(plain._id)) === 'move-dst',
		JSON.stringify(moved)
	);

	const elsewhere = await bucketIn('move-third');
	const refused = await ownership.moveBucket(elsewhere._id, src, 'move-dst');
	check(
		'a bucket move changes nothing when the bucket is not in the group it is said to leave',
		refused.status === 'conflict' &&
			(await ownerOf(elsewhere._id)) === 'move-third'
	);

	const raced = await bucketIn(src);
	const outcomes = await Promise.all([
		ownership.moveBucket(raced._id, src, 'move-a'),
		ownership.moveBucket(raced._id, src, 'move-b')
	]);
	check(
		'two simultaneous moves of one bucket: exactly one wins',
		outcomes.filter((o) => o.status === 'moved').length === 1,
		`${outcomes.map((o) => o.status).join(', ')}; bucket in ${String(await ownerOf(raced._id))}`
	);

	await audit.record({
		actorId: 'fidelity',
		actorEmail: 'fidelity@x.io',
		action: 'bucket.owner.change',
		targetType: 'UserBucket',
		targetId: plain._id,
		ownerGroupId: 'move-dst',
		formerOwnerGroupId: src
	});
	const left = await audit.list({
		ownerGroupIds: [src],
		targetId: plain._id
	});
	const joined = await audit.list({
		ownerGroupIds: ['move-dst'],
		targetId: plain._id
	});
	check(
		'a move is read by the group it left and by the group it joined',
		left.total === 1 && joined.total === 1,
		`${String(left.total)} / ${String(joined.total)}`
	);
}

/*
 * The personal-group repair as the migration leaves it, read back through the stores: the owner alone, as
 * owner, and one entry in the trail per repaired group. `seed` writes a legacy shared personal group in the
 * backend's raw form; `apply` runs the migration's half once.
 */
export async function verifyPersonalGroupRepair(
	stores: { groups: GroupStoreInstance; audit: AdminAuditStoreInstance },
	seed: (groupId: string) => Promise<void>,
	apply: () => Promise<unknown>,
	check: Check
): Promise<void> {
	const groupId = `fidelity-personal-${String(Date.now())}`;
	await seed(groupId);
	const report = await apply();
	await apply();
	const group = await stores.groups.find(groupId);
	const trail = await stores.audit.list({ targetId: groupId });
	check(
		'the upgrade leaves a shared personal group with its owner alone, as owner',
		/* Compared by field, not as a string: jsonb returns a document's keys in its own order. */
		group?.members.length === 1 &&
			group.members[0]?.userId === 'owner' &&
			group.members[0]?.role === 'owner',
		JSON.stringify(group?.members)
	);
	check(
		'the upgrade records one entry per repaired group, by the migration, counting the removed, even applied twice',
		trail.total === 1 &&
			trail.entries[0]?.actorId === 'system:migration' &&
			trail.entries[0]?.cascade?.members === 2,
		JSON.stringify(trail.entries)
	);
	if (Array.isArray(report)) {
		for (const line of report) console.log(`       ${String(line)}`);
	}
}
