/*
 * The specs/090 storage against a real datastore: the four conditional transitions of a bucket's scheduled
 * destruction each decide their race in one statement — a second schedule is refused and keeps the first date,
 * a restore is refused while a destruction holds a live claim and allowed once it lapses, two claims at one
 * moment give one winner, a claim for a due destruction is refused before the date, a re-claim keeps the record
 * of the audit entry, and a restore removes the field outright — and the dates read back as dates.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_090_bucket_deletion.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_090_bucket_deletion.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. Everything it writes belongs to ids unique to the run and is
 * removed at the end. It refuses a database whose name does not say it is disposable, as the other verify
 * scripts do.
 *
 * A script rather than a spec (Constitution Principle III): `bun test` runs the in-memory store, which
 * test/storage_contract/bucket_deletion.spec.ts holds to the same cases.
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
const { getBucketStore, getUserStore } =
	await import('../lib/adapters/index.js');
const { STORE_AREAS } = await import('../lib/consts/storage_inventory.js');
const { UNASSIGNED_GROUP_ID } = await import('../lib/admin/consts.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const MINUTE = 60 * 1000;
const stamp = `${Date.now()}`;
const store = getBucketStore();
const at = (minute: number) => new Date(Date.UTC(2026, 9, 12, 12, minute));
const created: string[] = [];

async function bucket(label: string): Promise<string> {
	const b = await store.create({
		_id: `v090-${label}-${stamp}`,
		name: `v090 ${label}`,
		slug: `v090-${label}-${stamp}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	created.push(b._id);
	return b._id;
}

function schedule(scheduledAt: Date, purgeAt: Date) {
	return {
		scheduledAt,
		purgeAt,
		scheduledBy: { userId: 'v090-admin', email: 'v090@example.com' }
	};
}

/* Whether the stored document carries the key at all, read past the store's own projection. */
async function storedHasDeletion(id: string): Promise<boolean> {
	if (mongo) {
		const { db } = await import('../lib/adapters/mongodb/db.js');
		const doc = await db
			.collection<{ _id: string }>(STORE_AREAS.userBuckets)
			.findOne({ _id: id });
		return doc !== null && 'deletion' in doc;
	}
	const { sql } = await import('../lib/adapters/postgres/index.js');
	const handle = sql();
	const rows = await handle<{ has: boolean }[]>`
		SELECT doc ? 'deletion' AS has FROM ${handle(STORE_AREAS.userBuckets)} WHERE id = ${id}
	`;
	return rows.at(0)?.has ?? false;
}

try {
	const twice = await bucket('twice');
	const first = await store.scheduleDeletion(twice, schedule(at(0), at(30)));
	const second = await store.scheduleDeletion(twice, schedule(at(5), at(60)));
	const held = await store.find(twice);
	check(
		'a second schedule is refused and keeps the first date',
		first !== null &&
			second === null &&
			held?.deletion?.purgeAt.getTime() === at(30).getTime()
	);
	check(
		'the dates read back as Dates',
		held?.deletion?.purgeAt instanceof Date &&
			held.deletion.scheduledAt instanceof Date &&
			held.deletion.scheduledBy.email === 'v090@example.com'
	);

	const claimed = await bucket('claimed');
	await store.scheduleDeletion(claimed, schedule(at(0), at(30)));
	await store.claimPurge(claimed, at(1), at(16), { due: false });
	check(
		'a restore is refused while a destruction holds a live claim',
		(await store.cancelDeletion(claimed, at(10))) === null &&
			(await store.find(claimed))?.deletion !== undefined
	);
	const restored = await store.cancelDeletion(claimed, at(17));
	check(
		'a restore is allowed once the claim lapses, and removes the field',
		restored !== null &&
			restored.deletion === undefined &&
			(await store.find(claimed))?.deletion === undefined
	);
	check(
		'a restored bucket’s stored document no longer holds the key',
		!(await storedHasDeletion(claimed))
	);

	const raced = await bucket('raced');
	await store.scheduleDeletion(raced, schedule(at(0), at(30)));
	const winners = (
		await Promise.all([
			store.claimPurge(raced, at(31), at(46), { due: true }),
			store.claimPurge(raced, at(31), at(46), { due: true }),
			store.claimPurge(raced, at(31), at(46), { due: true })
		])
	).filter((b) => b !== null);
	check('claims at one moment give one winner', winners.length === 1);

	const early = await bucket('early');
	await store.scheduleDeletion(early, schedule(at(0), at(30)));
	check(
		'a claim for a due destruction is refused before its date',
		(await store.claimPurge(early, at(29), at(44), { due: true })) === null
	);
	check(
		'a claim for Delete now is not held to the date',
		(await store.claimPurge(early, at(29), at(44), { due: false })) !== null
	);

	const recorded = await bucket('recorded');
	await store.scheduleDeletion(recorded, schedule(at(0), at(30)));
	await store.claimPurge(recorded, at(31), at(46), { due: true });
	await store.markPurgeRecorded(recorded, at(32));
	const reclaimed = await store.claimPurge(
		recorded,
		new Date(at(46).getTime() + MINUTE),
		at(62),
		{ due: true }
	);
	check(
		'a re-claim after the claim lapsed keeps the record of the audit entry',
		reclaimed?.deletion?.purge?.recordedAt?.getTime() === at(32).getTime() &&
			reclaimed.deletion.purge.claimedUntil.getTime() === at(62).getTime()
	);
	check(
		'a scheduled bucket is still found by its address',
		(await store.findBySlug(`v090-recorded-${stamp}`))?._id === recorded
	);
} finally {
	for (const id of created) {
		await getUserStore(id).destroyArea();
		await store.destroy(id);
	}
}

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
