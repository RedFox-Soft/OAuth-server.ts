import { MongoClient, ServerApiVersion } from 'mongodb';

import { STORE_AREAS, userAreaFor } from '../lib/consts/storage_inventory.js';
import {
	ADMIN_BUCKET_ID,
	ADMIN_PROJECT_ID,
	UNASSIGNED_GROUP_ID
} from '../lib/admin/consts.js';

/*
 * Storage-fidelity check for the `managedBy` -> `ownerGroupId` ownership migration.
 *
 * Constitution III permits a suite that uses a real database, under three conditions: it must be
 * invoked separately, must not be reachable from the default run, and must be confined to properties
 * an in-memory double cannot exhibit. This is that suite for this feature, and it is a standalone
 * script rather than a spec file precisely so `bun test` can never reach it.
 *
 * What it covers that `test/admin/migration_ownership.spec.ts` cannot: the mapping rule is already
 * proved there, hermetically. What is NOT provable without a database is the round trip — that the
 * documents are actually rewritten, that `managedBy` is actually gone afterwards, that a second run is
 * a no-op rather than a reshuffle, and that the reserved containers were skipped. Those are properties
 * of the write, not of the arithmetic.
 *
 * It exercises the REAL migration by shelling out to `database/mongodb.ts`. Reimplementing the apply
 * step here would create a second copy of the thing under test, which is the drift this repo's
 * enumeration tables exist to prevent.
 *
 *   bun database/verify_migration.ts
 *
 * DESTRUCTIVE. It creates and drops collections. It refuses to run unless DATABASE_NAME names a
 * throwaway database (see the guard below), so it cannot be pointed at production by a stray shell.
 */

const { MONGODB_URI, DATABASE_NAME } = process.env;

if (!MONGODB_URI || !DATABASE_NAME) {
	throw new Error(
		'MONGODB_URI and DATABASE_NAME must be provided as an env var'
	);
}

/*
 * The blast-radius guard, and the reason this script is safe to hand to somebody.
 *
 * A migration check has to write to a real database, so the only thing standing between it and
 * somebody's tenants is which database it is pointed at. Requiring the name to say out loud that it is
 * disposable makes the dangerous case impossible to reach by accident — `DATABASE_NAME=OAuth` simply
 * does not run — while costing a deliberate user one word.
 */
const THROWAWAY =
	/(^|[-_])(test|tmp|scratch|throwaway|migrationcheck)([-_]|$)/i;
if (!THROWAWAY.test(DATABASE_NAME)) {
	throw new Error(
		`refusing to run against '${DATABASE_NAME}': this script drops collections, so it only runs ` +
			`against a database whose name marks it disposable (contains test/tmp/scratch/throwaway/` +
			`migrationcheck). Point DATABASE_NAME at a scratch database and run it again.`
	);
}

const client = new MongoClient(MONGODB_URI, {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true
	}
});
const db = (await client.connect()).db(DATABASE_NAME);

const failures: string[] = [];
function check(ok: boolean, what: string): void {
	if (ok) {
		console.log(`  ok   ${what}`);
	} else {
		failures.push(what);
		console.log(`  FAIL ${what}`);
	}
}

/* The estate the migration has to preserve access across. Mirrors the hermetic spec's mixed case. */
const ADMINS = [
	{ _id: 'alice', email: 'alice@example.com' },
	{ _id: 'bob', email: 'bob@example.com' },
	{ _id: 'carol', email: 'carol@example.com' }
];
const LEGACY_PROJECTS = [
	{ _id: 'p-none', slug: 'p-none', managedBy: [] },
	{ _id: 'p-alice', slug: 'p-alice', managedBy: ['alice'] },
	{ _id: 'p-ab', slug: 'p-ab', managedBy: ['alice', 'bob'] },
	// Same set, written in the other order: must land in the SAME group as p-ab.
	{ _id: 'p-ba', slug: 'p-ba', managedBy: ['bob', 'alice'] },
	// Overlaps p-ab by one manager: must land in a DIFFERENT group. This is the cross-tenant leak.
	{ _id: 'p-ac', slug: 'p-ac', managedBy: ['alice', 'carol'] }
];
const LEGACY_BUCKETS = [
	{ _id: 'b-carol', managedBy: ['carol'] },
	{ _id: 'b-ab', managedBy: ['alice', 'bob'] }
];

async function seed(): Promise<void> {
	console.log(`seeding pre-migration fixtures into '${DATABASE_NAME}'`);
	for (const name of [
		STORE_AREAS.projects,
		STORE_AREAS.userBuckets,
		STORE_AREAS.groups,
		userAreaFor(ADMIN_BUCKET_ID)
	]) {
		await db.collection(name).deleteMany({});
	}

	const now = new Date();
	await db.collection(userAreaFor(ADMIN_BUCKET_ID)).insertMany(
		ADMINS.map((a) => ({
			...a,
			password: 'x',
			roles: ['project_admin'],
			active: true,
			verified: true,
			createdAt: now,
			updatedAt: now,
			lastLoginAt: null
		}))
	);
	await db.collection(STORE_AREAS.projects).insertMany(
		LEGACY_PROJECTS.map((p) => ({
			...p,
			name: p._id,
			type: 'regular',
			bucketId: null,
			clientIds: [],
			corsOrigins: [],
			createdAt: now,
			updatedAt: now
		}))
	);
	await db.collection(STORE_AREAS.userBuckets).insertMany(
		LEGACY_BUCKETS.map((b) => ({
			...b,
			name: b._id,
			roles: [],
			passwordLogin: true,
			federation: [],
			registrationOpen: true,
			emailVerificationRequired: false,
			verificationMethod: 'link',
			createdAt: now,
			updatedAt: now
		}))
	);
}

/* Who could reach a container before: exactly the administrators its manager list named. */
function reachBefore(managedBy: string[]): Set<string> {
	return new Set(managedBy);
}

/* Who can reach it after: the members of the group that owns it. */
async function reachAfter(ownerGroupId: string): Promise<Set<string>> {
	if (ownerGroupId === UNASSIGNED_GROUP_ID) return new Set();
	const group = await db
		.collection(STORE_AREAS.groups)
		.findOne({ _id: ownerGroupId as never });
	if (!group) return new Set();
	return new Set((group.members as { userId: string }[]).map((m) => m.userId));
}

async function runProvisioning(label: string): Promise<void> {
	console.log(`\nrunning the real migration (${label}) …`);
	const proc = Bun.spawnSync({
		cmd: ['bun', 'database/mongodb.ts'],
		env: { ...process.env, MONGODB_URI, DATABASE_NAME },
		stdout: 'pipe',
		stderr: 'pipe'
	});
	if (proc.exitCode !== 0) {
		console.log(new TextDecoder().decode(proc.stderr));
		throw new Error(`database/mongodb.ts exited ${proc.exitCode}`);
	}
}

async function ownerOf(area: string, id: string): Promise<string> {
	const doc = await db.collection(area).findOne({ _id: id as never });
	return (doc?.ownerGroupId as string) ?? '';
}

// ---------------------------------------------------------------- the checks

await seed();
await runProvisioning('first run');

console.log('\naccess is preserved for every container:');
for (const p of LEGACY_PROJECTS) {
	const after = await reachAfter(await ownerOf(STORE_AREAS.projects, p._id));
	const before = reachBefore(p.managedBy);
	check(
		[...after].sort().join(',') === [...before].sort().join(','),
		`${p._id}: {${[...before].sort()}} -> {${[...after].sort()}}`
	);
}
for (const b of LEGACY_BUCKETS) {
	const after = await reachAfter(await ownerOf(STORE_AREAS.userBuckets, b._id));
	const before = reachBefore(b.managedBy);
	check(
		[...after].sort().join(',') === [...before].sort().join(','),
		`${b._id}: {${[...before].sort()}} -> {${[...after].sort()}}`
	);
}

console.log('\nthe grouping rule held on real documents:');
const gAb = await ownerOf(STORE_AREAS.projects, 'p-ab');
const gBa = await ownerOf(STORE_AREAS.projects, 'p-ba');
const gAc = await ownerOf(STORE_AREAS.projects, 'p-ac');
const gBucketAb = await ownerOf(STORE_AREAS.userBuckets, 'b-ab');
check(gAb === gBa, 'identical manager sets share one group (p-ab, p-ba)');
check(
	gAb !== gAc,
	'overlapping manager sets do NOT share a group (p-ab vs p-ac) — the cross-tenant leak'
);
check(
	gBucketAb === gAb,
	'a bucket and a project with the same manager set share one group'
);
check(
	(await ownerOf(STORE_AREAS.projects, 'p-none')) === UNASSIGNED_GROUP_ID,
	'an unmanaged container goes to the reserved holding group'
);

console.log('\nthe write actually happened:');
const stillLegacy = await db
	.collection(STORE_AREAS.projects)
	.countDocuments({ managedBy: { $exists: true } });
const stillLegacyBuckets = await db
	.collection(STORE_AREAS.userBuckets)
	.countDocuments({ managedBy: { $exists: true } });
check(
	stillLegacy === 0 && stillLegacyBuckets === 0,
	'no document carries `managedBy` afterwards — a migration, not a shim'
);
check(
	(await db
		.collection(STORE_AREAS.groups)
		.countDocuments({ _id: UNASSIGNED_GROUP_ID as never })) === 1,
	'the reserved holding group exists'
);
check(
	(await db
		.collection(STORE_AREAS.groups)
		.countDocuments({ kind: 'personal' })) === ADMINS.length,
	'every administrator has exactly one personal group'
);
check(
	(await db
		.collection(STORE_AREAS.groups)
		.countDocuments({ needsReview: true })) === 2,
	'both multi-manager sets produced a group flagged for review'
);

console.log('\nthe reserved containers were skipped:');
const adminProject = await db
	.collection(STORE_AREAS.projects)
	.findOne({ _id: ADMIN_PROJECT_ID as never });
check(
	adminProject?.type === 'admin',
	'the reserved admin project is intact and still type `admin`'
);

/*
 * The property that makes the migration safe to re-run, which is what a deployment pipeline actually
 * does: `db:setup` runs on every release. A second pass must find nothing left to migrate and change
 * nothing — not reshuffle containers into fresh groups.
 */
console.log('\nre-running is a no-op:');
const groupsBefore = await db.collection(STORE_AREAS.groups).find().toArray();
await runProvisioning('second run');
const groupsAfter = await db.collection(STORE_AREAS.groups).find().toArray();
check(
	groupsBefore.length === groupsAfter.length,
	`group count unchanged (${groupsBefore.length})`
);
check(
	(await ownerOf(STORE_AREAS.projects, 'p-ab')) === gAb,
	'a container did not move on the second run'
);

/*
 * Drops the whole database, not just the four collections this script seeded.
 *
 * `database/mongodb.ts` is a full provisioning run: it creates every declared area, so one pass leaves
 * ~36 collections behind. Emptying only what was seeded left the rest as residue — untidy, and a slow
 * leak of confidence, because the next run would start against a database that already had indexes and
 * a config document, so "it passed" would stop meaning "it passed from nothing".
 *
 * Safe to drop unconditionally: the guard at the top of this file has already refused any database
 * whose name does not mark it disposable.
 */
console.log('\ncleaning up');
await db.dropDatabase();

await client.close();

if (failures.length > 0) {
	console.log(`\n${failures.length} check(s) FAILED:`);
	for (const f of failures) console.log(`  - ${f}`);
	process.exitCode = 1;
} else {
	console.log('\nall migration fidelity checks passed');
}
