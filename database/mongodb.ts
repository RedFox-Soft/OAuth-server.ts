import { MongoClient, ServerApiVersion } from 'mongodb';
import {
	FIXED_AREAS,
	STORE_AREAS,
	areaForBucket,
	type IndexSpec,
	type ModelAreaName,
	type StorageArea
} from '../lib/consts/storage_inventory.js';
import {
	applyIndexes,
	ensureCollection
} from '../lib/adapters/mongodb/provision.js';
import {
	duplicateEmailReport,
	exitCodeFor,
	missingIndexes,
	staleExpiryIndexes,
	toExistingIndexes,
	type DuplicateEmailRow,
	type ProvisioningSummary
} from './reconcile.js';
import { generateJWKS } from '../lib/helpers/jwks.js';
import { ISSUER } from '../lib/configs/env.js';
import {
	ADMIN_PROJECT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID
} from '../lib/admin/consts.js';
import { ADMIN_MCP_CLIENT_ID } from '../lib/mcp/consts.js';

if (!process.env.MONGODB_URI || !process.env.DATABASE_NAME) {
	throw new Error(
		'MONGODB_URI and DATABASE_NAME must be provided as an env var'
	);
}

const options = {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true
	}
};

const dbClient = new MongoClient(process.env.MONGODB_URI, options);
const db = (await dbClient.connect()).db(process.env.DATABASE_NAME);

// Why a stale expiry index is being removed, stated per case rather than assumed: an area may hold
// permanent records, or expire on a different field, or carry a lifetime that disagrees with the
// declaration.
function dropReason(area: StorageArea): string {
	return area.reaped === null
		? 'this area holds permanent records'
		: `not the declared expiry rule (expires on ${area.reaped})`;
}

const summary: ProvisioningSummary = {
	collectionsCreated: 0,
	indexesCreated: 0,
	indexesDropped: 0,
	bucketsProcessed: 0,
	constraintsSkipped: 0
};

function describeIndex(spec: IndexSpec): string {
	const key = Object.keys(spec.key).join(', ');
	const options = [
		spec.unique === true ? 'unique' : undefined,
		spec.expireAfterSeconds !== undefined ? 'expiring' : undefined
	]
		.filter(Boolean)
		.join(' ');
	return `(${key})${options ? ` — ${options}` : ''}`;
}

/*
 * Provision one area to match its inventory entry. Every *decision* is delegated to the pure helpers
 * in ./reconcile.js and the application of them to lib/adapters/mongodb/provision.js — which
 * UserBucketStore.create also uses, so a bucket created at runtime is constrained by the same code
 * that runs here. This function therefore holds no per-collection knowledge; the if/else chain it
 * replaced is how three collections came to carry an expiry index for a field they never write.
 *
 * Reconciliation runs in both directions on every run. The additive half is what lets an existing
 * deployment gain a constraint it never had; the subtractive half is confined to expiry indexes and
 * reports every removal, because an index disappearing must never be something an operator discovers
 * later.
 *
 * `blockUnique` skips the unique constraints on this area while applying the rest — used when the
 * area's own data already violates one. `note` labels the creation line for areas whose name does not
 * speak for itself.
 */
async function provisionArea(
	area: StorageArea,
	{
		blockUnique = false,
		note = ''
	}: { blockUnique?: boolean; note?: string } = {}
): Promise<void> {
	if (await ensureCollection(db, area.name)) {
		console.log(`created collection ${area.name}${note}`);
		summary.collectionsCreated += 1;
	}

	const collection = db.collection(area.name);
	/*
	 * `indexes()` is the driver's typed equivalent of the listIndexes cursor round-trip this used to do,
	 * so the descriptors arrive as IndexDescriptionInfo rather than untyped documents and the mapper can
	 * narrow them without an assertion.
	 */
	const existing = toExistingIndexes(await collection.indexes());

	for (const name of staleExpiryIndexes(area, existing)) {
		await collection.dropIndex(name);
		console.log(
			`dropped expiry index ${name} on ${area.name} — ${dropReason(area)}`
		);
		summary.indexesDropped += 1;
	}

	const missing = missingIndexes(area, existing);
	const appliable = blockUnique
		? missing.filter((spec) => spec.unique !== true)
		: missing;
	summary.constraintsSkipped += missing.length - appliable.length;

	const { created, conflicted } = await applyIndexes(db, area.name, appliable);

	for (const spec of created) {
		console.log(`created index on ${area.name} ${describeIndex(spec)}`);
		summary.indexesCreated += 1;
	}
	for (const spec of conflicted) {
		console.error(
			`${area.name}: skipped index ${describeIndex(spec)} — an incompatible ` +
				'index of the same key already exists; drop it by hand and re-run'
		);
		summary.constraintsSkipped += 1;
	}
}

for (const area of FIXED_AREAS) {
	await provisionArea(area);
}

// Provision the initial signing key at schema-creation time so a freshly created database already
// holds a persisted RS256 signing key. The runtime loader (lib/configs/keys.ts) keeps an equivalent
// generate-on-empty fallback for the in-memory adapter and any un-provisioned store.
const jwks = db.collection(STORE_AREAS.jwks);
if ((await jwks.countDocuments()) === 0) {
	const {
		keys: [key]
	} = await generateJWKS('RS256');
	await jwks.insertOne({ ...key, updatedAt: new Date() });
}

// Idempotent seed of the reserved admin project + bucket + OAuth client. Written
// against this script's own `db` connection (not the app singletons in
// lib/admin/seed.ts) to avoid opening a second connection from a one-shot script.
// The `Client` document mirrors the shape `adapter('Client').upsert` persists
// (lib/adapters/mongodb/mongoAdapter.ts): `{ _id, payload }`, with no `expiresAt`
// since this client never expires.
const seedNow = new Date();
await db.collection(STORE_AREAS.userBuckets).updateOne(
	{ _id: ADMIN_BUCKET_ID },
	{
		$setOnInsert: {
			name: 'Administrators',
			managedBy: [],
			roles: ['super_admin', 'project_admin'],
			// The reserved admin bucket keeps password login and accepts no providers — see
			// lib/admin/seed.ts, which this mirrors. Changing one seed and not the other is how a seed
			// change silently no-ops in production: db:setup runs this file, never that one.
			passwordLogin: true,
			federation: [],
			// the reserved admin bucket never accepts self-service registration
			registrationOpen: false,
			emailVerificationRequired: false,
			verificationMethod: 'link',
			createdAt: seedNow,
			updatedAt: seedNow
		}
	},
	{ upsert: true }
);
// The default ('redfox') bucket backs the pre-existing default user collection and
// every client not assigned to a project (see resolveBucketForClient). Seeded here
// so it is manageable in the admin Buckets UI. Mirrors ensureAdminSeed (lib/admin/seed.ts),
// which db:setup does not call — this script owns the deployment seed.
await db.collection(STORE_AREAS.userBuckets).updateOne(
	{ _id: 'redfox' },
	{
		$setOnInsert: {
			name: 'Default users',
			managedBy: [],
			roles: [],
			passwordLogin: true,
			federation: [],
			registrationOpen: true,
			emailVerificationRequired: false,
			verificationMethod: 'link',
			createdAt: seedNow,
			updatedAt: seedNow
		}
	},
	{ upsert: true }
);
await db.collection(STORE_AREAS.projects).updateOne(
	{ _id: ADMIN_PROJECT_ID },
	{
		$setOnInsert: {
			name: 'Administration',
			slug: 'admin',
			type: 'admin',
			managedBy: [],
			bucketId: ADMIN_BUCKET_ID,
			clientIds: [ADMIN_CLIENT_ID, ADMIN_MCP_CLIENT_ID],
			createdAt: seedNow,
			updatedAt: seedNow
		}
	},
	{ upsert: true }
);
/*
 * An existing deployment's admin project predates the MCP agent client, and `$setOnInsert` above will
 * not touch it — so the id is added explicitly. Without it the client exists but belongs to no project,
 * `resolveBucketForClient` routes it to the default bucket, and an administrator cannot sign an agent in.
 */
await db.collection(STORE_AREAS.projects).updateOne(
	{ _id: ADMIN_PROJECT_ID },
	{
		$addToSet: {
			clientIds: { $each: [ADMIN_CLIENT_ID, ADMIN_MCP_CLIENT_ID] }
		}
	}
);
/*
 * The seed writes straight to the model area, since a one-shot script has no adapter instance.
 * Annotated with the inventory's own type so a typo here cannot name a collection nothing provisions —
 * which is the class of defect this whole feature exists to remove.
 */
const CLIENT_AREA: ModelAreaName = 'Client';

await db.collection(CLIENT_AREA).updateOne(
	{ _id: ADMIN_CLIENT_ID },
	{
		$setOnInsert: {
			payload: {
				clientId: ADMIN_CLIENT_ID,
				applicationType: 'web',
				grantTypes: ['authorization_code'],
				responseTypes: ['code'],
				redirectUris: [`${ISSUER}/admin/callback`],
				token_endpoint_auth_method: 'none',
				'consent.require': false
			}
		}
	},
	{ upsert: true }
);

/*
 * The reserved MCP agent client. Kept in step with `ensureAdminSeed` deliberately: that function is
 * test-only, this script is what a real deployment runs, and a change made to one and not the other
 * silently no-ops in production while the suite stays green.
 *
 * Public with mandatory PKCE, so there is no secret to distribute, and native/loopback redirect URIs
 * because that is what a local MCP client can receive a code on.
 */
await db.collection(CLIENT_AREA).updateOne(
	{ _id: ADMIN_MCP_CLIENT_ID },
	{
		$setOnInsert: {
			payload: {
				clientId: ADMIN_MCP_CLIENT_ID,
				applicationType: 'native',
				grantTypes: ['authorization_code', 'refresh_token'],
				responseTypes: ['code'],
				redirectUris: [
					'http://127.0.0.1:33418/callback',
					'http://localhost:33418/callback',
					'http://127.0.0.1/callback'
				],
				token_endpoint_auth_method: 'none',
				'consent.require': true
			}
		}
	},
	{ upsert: true }
);

/*
 * Per-bucket end-user collections, one per bucket that exists. This MUST run after the seed above:
 * the `admin` and `redfox` buckets are created there, so provisioning the per-bucket areas first
 * would leave a fresh deployment with no user collections at all — and the run would still report
 * success. Buckets created later, through the admin control plane, are provisioned by
 * UserBucketStore.create instead.
 */
const buckets = await db
	.collection<{ _id: string }>(STORE_AREAS.userBuckets)
	.find({}, { projection: { _id: 1 } })
	.toArray();

/*
 * Addresses already duplicated in a bucket, which a unique index cannot be created over. Pre-checked
 * rather than left to createIndex's duplicate-key error, which names one offending value and says
 * nothing about the rest — an operator needs the whole list to clean it up.
 */
async function duplicateEmails(
	collection: string
): Promise<DuplicateEmailRow[]> {
	return db
		.collection(collection)
		.aggregate<DuplicateEmailRow>([
			{ $match: { email: { $type: 'string' } } },
			{ $group: { _id: '$email', count: { $sum: 1 } } },
			{ $match: { count: { $gt: 1 } } },
			{ $sort: { _id: 1 } }
		])
		.toArray();
}

for (const bucket of buckets) {
	const area = areaForBucket(bucket._id);
	/*
	 * Checked before the collection exists, which is safe: aggregating a missing collection yields an
	 * empty cursor rather than an error, and a collection that does not exist holds no duplicates.
	 * provisionArea below is the single place a bucket area is created, so it is reported once.
	 */
	const report = duplicateEmailReport(
		bucket._id,
		await duplicateEmails(area.name)
	);
	if (report) {
		console.error(report);
	}

	// Everything except the blocked unique constraint is still applied: one bucket's bad data must not
	// leave the rest of that bucket — or any other — unprovisioned.
	await provisionArea(area, {
		blockUnique: report !== null,
		note: ` for bucket ${bucket._id}`
	});
	summary.bucketsProcessed += 1;
}

console.log(
	`\nprovisioning complete: ${summary.collectionsCreated} collection(s) created, ` +
		`${summary.indexesCreated} index(es) created, ${summary.indexesDropped} stale ` +
		`expiry index(es) dropped, ${summary.bucketsProcessed} bucket(s) processed, ` +
		`${summary.constraintsSkipped} constraint(s) skipped`
);

await dbClient.close();

/*
 * Exit non-zero when a declared constraint is not in force, so a deployment pipeline cannot mistake
 * an incomplete run for a successful one. `exitCode` rather than `exit()`: the connection above is
 * already closed, and this lets any pending stdio flush.
 */
process.exitCode = exitCodeFor(summary);
