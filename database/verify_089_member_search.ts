/*
 * The specs/089 member search against a real datastore: the user store's `memberOf` filter, together with the
 * console's prefix search, answers only members of the one group — never a matching non-member, never a member
 * of another group — by email prefix and by username prefix in any letter case, with an exact total and pages
 * that tile the matches.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_089_member_search.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_089_member_search.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. Everything it writes belongs to a bucket unique to the run and is
 * removed at the end. It refuses a database whose name does not say it is disposable, as the other verify
 * scripts do.
 *
 * A script rather than a spec (Constitution Principle III): `bun test` runs the in-memory store, which
 * test/bucket_groups/member_search.spec.ts holds to the same cases through the admin route.
 */

const THROWAWAY =
	/(^|[-_])(test|tmp|scratch|throwaway|migrationcheck)([-_]|$)/i;

const mongo = process.env.MONGODB_URI;
const postgres = process.env.POSTGRES_URL;
if (Boolean(mongo) === Boolean(postgres)) {
	console.error('set exactly one of MONGODB_URI and POSTGRES_URL');
	process.exit(1);
}
const database = mongo
	? (process.env.DATABASE_NAME ?? '')
	: new URL(postgres ?? '').pathname.replace(/^\//, '');
if (!THROWAWAY.test(database)) {
	console.error(
		`refusing to run against '${database}': the database name must contain test, tmp, scratch, ` +
			'throwaway or migrationcheck as a whole word.'
	);
	process.exit(1);
}

/* After the guard, for the reason verify_postgres.ts gives: importing the adapters connects. */
const { getBucketGroupStore, getBucketStore, getUserStore } =
	await import('../lib/adapters/index.js');
const { UNASSIGNED_GROUP_ID } = await import('../lib/admin/consts.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const stamp = `${Date.now()}`;
const bucketId = `v089-${stamp}`;
const buckets = getBucketStore();
const groups = getBucketGroupStore();

await buckets.create({
	_id: bucketId,
	name: 'v089',
	slug: `v089-${stamp}`,
	ownerGroupId: UNASSIGNED_GROUP_ID
});

try {
	const users = getUserStore(bucketId);
	const ordinary = Array.from(
		{ length: 30 },
		(_, i) => `member${String(i).padStart(2, '0')}@x.io`
	);
	const anns = ['anna.member@x.io', 'anne.member@x.io', 'annie.member@x.io'];
	const members: string[] = [];
	for (const email of [...ordinary, ...anns]) {
		members.push((await users.create(email, 'h', true))._id);
	}
	members.push(
		(
			await users.create('z@x.io', 'h', true, undefined, {
				userName: 'Zed.Member'
			})
		)._id
	);
	const outsider = await users.create('anna.outsider@x.io', 'h', true);
	await users.create('member99@x.io', 'h', true);

	const group = await groups.create(
		{
			_id: `v089-large-${stamp}`,
			bucketId,
			displayName: `v089 large group ${stamp}`
		},
		members
	);
	/* Another group of the same bucket holding the outsider: membership elsewhere must not count. */
	await groups.create(
		{
			_id: `v089-other-${stamp}`,
			bucketId,
			displayName: `v089 other group ${stamp}`
		},
		[outsider._id]
	);

	const page = { startIndex: 1, count: 100 };
	const byEmail = await users.query(
		{ search: 'ANN', memberOf: group._id },
		page,
		'email'
	);
	check(
		'an email prefix in another letter case finds exactly the matching members',
		JSON.stringify(byEmail.users.map((u) => u.email)) ===
			JSON.stringify(anns) && byEmail.totalResults === anns.length,
		byEmail.users.map((u) => u.email).join(', ')
	);

	const byUserName = await users.query(
		{ search: 'zed', memberOf: group._id },
		page,
		'email'
	);
	check(
		'a username prefix finds the member',
		byUserName.users.map((u) => u.email).join() === 'z@x.io'
	);

	const first = await users.query(
		{ search: 'member', memberOf: group._id },
		{ startIndex: 1, count: 20 },
		'email'
	);
	const second = await users.query(
		{ search: 'member', memberOf: group._id },
		{ startIndex: 21, count: 20 },
		'email'
	);
	const seen = [...first.users, ...second.users].map((u) => u.email);
	check(
		'the total is exact and the pages tile the matches, with no non-member',
		first.totalResults === ordinary.length &&
			JSON.stringify(seen) === JSON.stringify(ordinary),
		`total ${first.totalResults}, seen ${seen.length}`
	);

	const none = await users.query(
		{ search: 'nobody-starts-like-this', memberOf: group._id },
		page,
		'email'
	);
	check(
		'no match answers an empty page',
		none.totalResults === 0 && none.users.length === 0
	);
} finally {
	await groups.destroyByBucket(bucketId);
	await getUserStore(bucketId).destroyArea();
	await buckets.destroy(bucketId);
}

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
