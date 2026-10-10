import type {
	AdminAuditStoreInstance,
	ContainerOwnershipStoreInstance,
	GroupStoreInstance,
	ProjectStoreInstance,
	UserBucketStoreInstance
} from '../lib/adapters/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/*
 * Moving containers between administrator groups, and the upgrade that made personal groups personal
 * (specs/075), against a real datastore: what an in-memory double cannot show is whether the move is one
 * change under two concurrent requests, and whether the migration's raw writes read back through the stores.
 * Shared by verify_mongodb.ts and verify_postgres.ts so both backends answer the same questions in the same
 * words.
 */
export async function verifyContainerOwnership(
	stores: {
		buckets: UserBucketStoreInstance;
		projects: ProjectStoreInstance;
		ownership: ContainerOwnershipStoreInstance;
		audit: AdminAuditStoreInstance;
	},
	check: Check
): Promise<void> {
	const { buckets, projects, ownership, audit } = stores;
	const stamp = Date.now();
	const src = `move-src-${stamp}`;

	async function bucketWith(owner: string, projectOwners: string[]) {
		const bucket = await buckets.create({
			name: `move-${stamp}-${Math.random()}`,
			ownerGroupId: owner
		});
		const bound = [];
		for (const [i, projectOwner] of projectOwners.entries()) {
			bound.push(
				await projects.create({
					name: `p${String(i)}`,
					slug: `move-${stamp}-${bucket._id}-${String(i)}`.toLowerCase(),
					ownerGroupId: projectOwner,
					bucketId: bucket._id
				})
			);
		}
		return { bucket, bound };
	}
	const ownerOf = async (id: string) => (await projects.find(id))?.ownerGroupId;

	const plain = await bucketWith(src, [src, src]);
	const moved = await ownership.moveBucket(plain.bucket._id, src, 'move-dst');
	check(
		'a bucket move carries the bucket and every project using it',
		moved.status === 'moved' &&
			moved.projectIds.length === 2 &&
			(await buckets.find(plain.bucket._id))?.ownerGroupId === 'move-dst' &&
			(await ownerOf(plain.bound[0]?._id ?? '')) === 'move-dst' &&
			(await ownerOf(plain.bound[1]?._id ?? '')) === 'move-dst',
		JSON.stringify(moved)
	);

	const stray = await bucketWith(src, [src, 'move-third']);
	const refused = await ownership.moveBucket(stray.bucket._id, src, 'move-dst');
	check(
		'a bucket move changes nothing when a project using it is in a third group',
		refused.status === 'conflict' &&
			(await buckets.find(stray.bucket._id))?.ownerGroupId === src &&
			(await ownerOf(stray.bound[0]?._id ?? '')) === src
	);

	const halfDone = await bucketWith(src, [src, src]);
	await buckets.update(halfDone.bucket._id, { ownerGroupId: 'move-dst' });
	const completed = await ownership.moveBucket(
		halfDone.bucket._id,
		src,
		'move-dst'
	);
	check(
		'repeating a move left after the bucket write completes it',
		completed.status === 'moved' &&
			(await ownerOf(halfDone.bound[1]?._id ?? '')) === 'move-dst'
	);

	const raced = await bucketWith(src, [src, src, src]);
	const outcomes = await Promise.all([
		ownership.moveBucket(raced.bucket._id, src, 'move-a'),
		ownership.moveBucket(raced.bucket._id, src, 'move-b')
	]);
	const winner = (await buckets.find(raced.bucket._id))?.ownerGroupId;
	const projectOwners = await Promise.all(
		raced.bound.map((p) => ownerOf(p._id))
	);
	check(
		'two simultaneous moves of one bucket: exactly one wins, and its projects follow the winner',
		outcomes.filter((o) => o.status === 'moved').length === 1 &&
			projectOwners.every((owner) => owner === winner),
		`${outcomes.map((o) => o.status).join(', ')}; bucket in ${String(winner)}, projects in ${projectOwners.join(', ')}`
	);

	const lone = await projects.create({
		name: 'lone',
		slug: `move-lone-${stamp}`,
		ownerGroupId: src
	});
	check(
		'a project with no bucket moves alone, and one using a bucket does not',
		(await ownership.moveProject(lone._id, src, 'move-dst')).status ===
			'moved' &&
			(await ownerOf(lone._id)) === 'move-dst' &&
			(await ownership.moveProject(stray.bound[0]?._id ?? '', src, 'move-dst'))
				.status === 'conflict'
	);

	await audit.record({
		actorId: 'fidelity',
		actorEmail: 'fidelity@x.io',
		action: 'bucket.owner.change',
		targetType: 'UserBucket',
		targetId: plain.bucket._id,
		ownerGroupId: 'move-dst',
		formerOwnerGroupId: src
	});
	const left = await audit.list({
		ownerGroupIds: [src],
		targetId: plain.bucket._id
	});
	const joined = await audit.list({
		ownerGroupIds: ['move-dst'],
		targetId: plain.bucket._id
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
