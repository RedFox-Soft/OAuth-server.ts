import { STORE_AREAS } from '../lib/consts/storage_inventory.js';
import { verifyEndUserIdentity } from './verify_end_user_identity.js';
import { verifyProvisioningConnections } from './verify_provisioning_connections.js';

/*
 * Storage fidelity for the MongoDB backend, against a real MongoDB — the properties of per-issuer
 * namespaces and bucket keys an in-memory double cannot exhibit.
 *
 *   MONGODB_URI=mongodb://localhost:27017 DATABASE_NAME=oauth_scratch_x  bun database/verify_mongodb.ts
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
	BucketKeysStore,
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
