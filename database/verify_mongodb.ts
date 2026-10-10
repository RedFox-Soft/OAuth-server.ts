import { STORE_AREAS } from '../lib/consts/storage_inventory.js';
import { verifyEndUserIdentity } from './verify_end_user_identity.js';
import { verifyProvisioningConnections } from './verify_provisioning_connections.js';
import { verifyBucketGroups } from './verify_bucket_groups.js';
import { verifyActivity } from './verify_activity.js';
import {
	verifyContainerOwnership,
	verifyPersonalGroupRepair
} from './verify_container_ownership.js';

/*
 * Storage fidelity for the MongoDB backend, against a real MongoDB — the properties of per-issuer
 * namespaces and bucket keys an in-memory double cannot exhibit.
 *
 *   MONGODB_URI=mongodb://localhost:27017 DATABASE_NAME=oauth_scratch_x  bun run db:setup
 *   MONGODB_URI=mongodb://localhost:27017 DATABASE_NAME=oauth_scratch_x  bun database/verify_mongodb.ts
 *
 * Provision the database before every run: the uniqueness checks are the provisioned indexes' to pass, and the
 * script drops the database when it is done.
 *
 * DESTRUCTIVE, and refuses any database whose name does not say it is disposable — the guard
 * `verify_postgres.ts` carries, for the same reason. A script rather than a spec, so `bun test` can
 * never reach it (Constitution Principle III).
 */

const THROWAWAY =
	/(^|[-_])(test|tmp|scratch|throwaway|migrationcheck)([-_]|$)/i;

const database = process.env.DATABASE_NAME ?? '';
if (!process.env.MONGODB_URI || !THROWAWAY.test(database)) {
	console.error(
		`refusing to run against '${database}': set MONGODB_URI and a DATABASE_NAME containing test, tmp, ` +
			'scratch, throwaway or migrationcheck as a whole word.'
	);
	process.exit(1);
}
delete process.env.POSTGRES_URL;

/* After the guard, for the reason verify_postgres.ts gives: importing the adapters connects. */
const {
	ActivityStore,
	AdminAuditStore,
	BucketGroupStore,
	BucketKeysStore,
	ContainerOwnershipStore,
	GroupStore,
	ProjectStore,
	ProtectedResourceStore,
	ProvisioningConnectionStore,
	UserBucketStore,
	UserStore
} = await import('../lib/adapters/mongodb/index.js');
const { db } = await import('../lib/adapters/mongodb/db.js');
const { MIGRATIONS } = await import('../lib/consts/migrations.js');
const { generateJWKS } = await import('../lib/helpers/jwks.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const stamp = Date.now();
const resources = new ProtectedResourceStore();

const identifier = `https://fidelity.invalid/api/${stamp}`;
const declaredTwice = await Promise.allSettled(
	['first', 'second'].map((name) =>
		resources.create({
			namespace: '@root',
			identifier,
			projectId: 'fidelity',
			name,
			scopes: ['read']
		})
	)
);
check(
	'two simultaneous declarations of one identifier in one namespace: exactly one wins',
	declaredTwice.filter((r) => r.status === 'fulfilled').length === 1,
	declaredTwice.map((r) => r.status).join(', ')
);

const bucketKeys = new BucketKeysStore();
const claimBucket = `fidelity-bucket-${stamp}`;
const {
	keys: [material]
} = await generateJWKS('RS256');
const claimedBy = await Promise.all(
	['first', 'second', 'third'].map((kid) =>
		bucketKeys.createIfAbsent({
			_id: `${claimBucket} #initial`,
			bucketId: claimBucket,
			kid: `${claimBucket}-${kid}`,
			jwk: { ...material, kid: `${claimBucket}-${kid}` },
			alg: 'RS256',
			use: 'sig',
			state: 'signing',
			createdAt: new Date(),
			stateChangedAt: new Date()
		})
	)
);
check(
	'three simultaneous first keys for one bucket: exactly one is stored',
	claimedBy.filter(Boolean).length === 1 &&
		(await bucketKeys.listByBucket(claimBucket)).length === 1,
	claimedBy.join(', ')
);

/* No multi-document transaction on a standalone mongod, so the store undoes its own copies. */
const moveProject = `fidelity-move-${stamp}`;
for (const suffix of ['a', 'b']) {
	await resources.create({
		namespace: `${moveProject}-from`,
		identifier: `https://move.invalid/${suffix}`,
		projectId: moveProject,
		name: suffix,
		scopes: ['read']
	});
}
await resources.create({
	namespace: `${moveProject}-to`,
	identifier: 'https://move.invalid/b',
	projectId: 'someone-else',
	name: 'taken',
	scopes: ['read']
});
const refused = await resources.moveProject(
	moveProject,
	`${moveProject}-from`,
	`${moveProject}-to`
);
check(
	'a move into a namespace already declaring one identifier moves nothing',
	'conflicts' in refused &&
		(await resources.find(`${moveProject}-from`, 'https://move.invalid/a')) !==
			null &&
		(await resources.find(`${moveProject}-to`, 'https://move.invalid/a')) ===
			null,
	JSON.stringify(refused)
);

const namespacing = MIGRATIONS.find((m) =>
	m.id.endsWith('protected-resources-namespaced')
);
const legacyBucket = `fidelity-legacy-bucket-${stamp}`;
const legacyProject = `fidelity-legacy-project-${stamp}`;
const legacyIdentifier = `https://legacy.invalid/${stamp}`;
await db.collection<{ _id: string }>(STORE_AREAS.userBuckets).insertOne({
	_id: legacyBucket,
	name: 'legacy',
	slug: `legacy${stamp}`
} as {
	_id: string;
});
await db
	.collection<{ _id: string }>(STORE_AREAS.projects)
	.insertOne({ _id: legacyProject, bucketId: legacyBucket } as { _id: string });
await db.collection<{ _id: string }>(STORE_AREAS.protectedResources).insertOne({
	_id: legacyIdentifier,
	projectId: legacyProject,
	name: 'legacy',
	scopes: ['read'],
	tokenFormat: 'jwt',
	accessTokenTTL: 900,
	trailingSlashSignificant: false,
	createdAt: new Date(),
	updatedAt: new Date()
} as { _id: string });
if (namespacing && !('noop' in namespacing.mongodb)) {
	await namespacing.mongodb.apply(db);
	await namespacing.mongodb.apply(db);
}
const rekeyed = await resources.find(legacyBucket, legacyIdentifier);
const forProject = await db
	.collection(STORE_AREAS.protectedResources)
	.countDocuments({ projectId: legacyProject });
check(
	'the namespacing migration re-keys a legacy declaration once, applied twice',
	rekeyed?.identifier === legacyIdentifier && forProject === 1,
	`${forProject} document(s) for the project`
);

/*
 * The root keys migration, against legacy flat keys in the order MongoDB returns them: two RS256 keys, an
 * ES256 key and an encryption key. The first RS256 key in natural order signed before the upgrade and must
 * be the one that signs after it; applying the migration twice must change nothing.
 */
const rootKeys = MIGRATIONS.find((m) => m.id.endsWith('root-keys-lifecycle'));
const { LEGACY_ROOT_KEYS_AREA } = await import('../lib/consts/migrations.js');
const { ROOT_KEY_OWNER } = await import('../lib/consts/key_owner.js');
const legacyArea = db.collection<Record<string, unknown>>(
	LEGACY_ROOT_KEYS_AREA
);
/*
 * A provisioned scratch database — which the uniqueness checks above need — already holds the root key
 * `db:setup` generated, and one kept between runs holds the last run's. The migration then finds a signer it did
 * not create and the count is off by one: the fixture must start from no root keys, as verify_postgres.ts's does.
 * Not a state an upgrade reaches: `db:setup` generates no root key while legacy keys await the migration.
 */
await legacyArea.deleteMany({});
await db
	.collection(STORE_AREAS.bucketKeys)
	.deleteMany({ bucketId: ROOT_KEY_OWNER });
const [firstRsa, secondRsa, ec] = await Promise.all([
	generateJWKS('RS256'),
	generateJWKS('RS256'),
	generateJWKS('ES256')
]).then((sets) => sets.map((set) => set.keys[0]));
await legacyArea.insertMany([
	{ ...firstRsa, updatedAt: new Date() },
	{ ...secondRsa, updatedAt: new Date() },
	{ ...ec, updatedAt: new Date() },
	{
		...firstRsa,
		kid: `enc-${stamp}`,
		alg: 'RSA-OAEP-256',
		use: 'enc',
		updatedAt: new Date()
	}
]);
if (rootKeys && !('noop' in rootKeys.mongodb)) {
	await rootKeys.mongodb.apply(db);
	await rootKeys.mongodb.apply(db);
}
const migrated = await new BucketKeysStore().listByBucket(ROOT_KEY_OWNER);
const stateOf = (kid: string) => migrated.find((key) => key.kid === kid)?.state;
check(
	'the root keys migration keeps the key that signed, per algorithm, applied twice',
	migrated.length === 4 &&
		stateOf(firstRsa.kid) === 'signing' &&
		stateOf(secondRsa.kid) === 'published' &&
		stateOf(ec.kid) === 'signing' &&
		stateOf(`enc-${stamp}`) === 'published' &&
		(await legacyArea.countDocuments()) === 0,
	migrated.map((key) => `${key.alg}:${key.state}`).join(', ')
);

/*
 * Roles to groups (specs/071), against legacy records as a release before it wrote them: a bucket declaring
 * roles, its users holding them — one in two spellings, one undeclared, one blank — and administrators holding
 * super_admin (one deactivated) and project_admin. Applied twice; the second application must change nothing.
 */
const rolesMigration = MIGRATIONS.find((m) => m.id.endsWith('roles-to-groups'));
const rolesBucket = `fidelity-roles-${stamp}`;
await db.collection<{ _id: string }>(STORE_AREAS.userBuckets).insertOne({
	_id: rolesBucket,
	name: 'roles',
	ownerGroupId: 'unassigned',
	roles: ['editor', 'viewer']
} as { _id: string });
/* Raw legacy documents, in the shape the release before this one wrote. */
type Raw = { _id: string } & Record<string, unknown>;
await db.collection<Raw>(`user_${rolesBucket}`).insertMany([
	{ _id: 'u1', email: 'u1@x.io', roles: ['editor'] },
	{ _id: 'u2', email: 'u2@x.io', roles: ['Editor', 'viewer'] },
	{ _id: 'u3', email: 'u3@x.io', roles: ['auditor', '  '] }
]);
await db.collection<Raw>('user_admin').insertMany([
	{
		_id: `root-${stamp}`,
		email: 'root@x.io',
		active: true,
		roles: ['super_admin', 'project_admin']
	},
	{
		_id: `retired-${stamp}`,
		email: 'retired@x.io',
		active: false,
		roles: ['super_admin']
	},
	{
		_id: `pa-${stamp}`,
		email: 'pa@x.io',
		active: true,
		roles: ['project_admin']
	}
]);
const snapshot = async () => ({
	groups: await db
		.collection(STORE_AREAS.bucketGroups)
		.countDocuments({ bucketId: rolesBucket }),
	memberships: await db
		.collection(STORE_AREAS.bucketGroupMembers)
		.countDocuments({ bucketId: rolesBucket })
});
let roleReport: readonly string[] = [];
let afterFirst = { groups: -1, memberships: -1 };
if (rolesMigration && !('noop' in rolesMigration.mongodb)) {
	const lines = await rolesMigration.mongodb.apply(db);
	roleReport = Array.isArray(lines) ? lines.map(String) : [];
	afterFirst = await snapshot();
	await rolesMigration.mongodb.apply(db);
}
const bucketGroupStore = new BucketGroupStore();
const migratedGroups = (
	await bucketGroupStore.query(
		{ bucketId: rolesBucket },
		{ startIndex: 1, count: 100 }
	)
).groups;
const membersByName: Record<string, string[]> = {};
for (const group of migratedGroups) {
	membersByName[group.displayName] = await bucketGroupStore.memberIds(
		group._id
	);
}
check(
	'every declared and held role becomes a group with exactly its holders',
	JSON.stringify(membersByName) ===
		JSON.stringify({ auditor: ['u3'], editor: ['u1', 'u2'], viewer: ['u2'] }) ||
		JSON.stringify(Object.fromEntries(Object.entries(membersByName).sort())) ===
			JSON.stringify({ auditor: ['u3'], editor: ['u1', 'u2'], viewer: ['u2'] }),
	JSON.stringify(membersByName)
);
const superGroup = await db
	.collection<Raw>('groups')
	.findOne({ _id: 'super-administrators' });
const superMembers = ((superGroup?.members ?? []) as { userId: string }[]).map(
	(m) => m.userId
);
check(
	'every super_admin holder, active or not, and nobody else, is a member of Super administrators',
	superMembers.includes(`root-${stamp}`) &&
		superMembers.includes(`retired-${stamp}`) &&
		!superMembers.includes(`pa-${stamp}`),
	superMembers.join(', ')
);
check(
	'the roles migration applied twice changes nothing the second time',
	JSON.stringify(await snapshot()) === JSON.stringify(afterFirst),
	JSON.stringify(afterFirst)
);
check(
	'no migrated record still carries roles',
	(await db
		.collection(`user_${rolesBucket}`)
		.countDocuments({ roles: { $exists: true } })) === 0 &&
		(await db
			.collection('user_admin')
			.countDocuments({ roles: { $exists: true } })) === 0 &&
		(await db
			.collection(STORE_AREAS.userBuckets)
			.countDocuments({ roles: { $exists: true } })) === 0
);
for (const line of roleReport) console.log(`       ${line}`);
for (const line of await verifyBucketGroups(bucketGroupStore, check)) {
	console.log(`       ${line}`);
}

/*
 * Monthly and daily active users per bucket (specs/076). MongoDB's TTL monitor runs on its own schedule and
 * cannot be asked to, so reclamation here is the TTL index on `expiresAt` being in place.
 */
await verifyActivity(
	new ActivityStore(),
	async () =>
		(await db.collection(STORE_AREAS.activityMarks).indexes()).some(
			(index) => index.key.expiresAt === 1 && index.expireAfterSeconds === 0
		),
	check
);

/* Moving containers between groups, and making personal groups personal again (specs/075). */
{
	const moveBuckets = new UserBucketStore();
	const moveProjects = new ProjectStore();
	const moveAudit = new AdminAuditStore();
	await verifyContainerOwnership(
		{
			buckets: moveBuckets,
			projects: moveProjects,
			ownership: new ContainerOwnershipStore(),
			audit: moveAudit
		},
		check
	);
	const repair = MIGRATIONS.find((m) =>
		m.id.endsWith('personal-groups-single-member')
	);
	await verifyPersonalGroupRepair(
		{ groups: new GroupStore(), audit: moveAudit },
		async (groupId) => {
			await db.collection<Raw>(STORE_AREAS.groups).insertOne({
				_id: groupId,
				name: 'owner@x.io',
				kind: 'personal',
				members: [
					{ userId: 'owner', role: 'owner' },
					{ userId: 'colleague', role: 'owner' },
					{ userId: 'viewer', role: 'member' }
				],
				createdAt: new Date(),
				updatedAt: new Date()
			});
		},
		async () =>
			repair && !('noop' in repair.mongodb)
				? repair.mongodb.apply(db)
				: undefined,
		check
	);
}

/* A bucket created here, so its user area carries the indexes declared today. */
const identityBucket = await new UserBucketStore().create({
	name: `identity-${stamp}`,
	ownerGroupId: 'unassigned'
});
await verifyEndUserIdentity(new UserStore(identityBucket._id), check);
await verifyProvisioningConnections(new ProvisioningConnectionStore(), check);

console.log(
	`\n${failures === 0 ? 'all fidelity checks passed' : `${failures} check(s) FAILED`}`
);
await db.dropDatabase();
process.exit(failures === 0 ? 0 : 1);
