import { MongoClient, ServerApiVersion } from 'mongodb';
import { COLLECTIONS } from './collections';
import { generateJWKS } from '../lib/helpers/jwks.js';
import { ISSUER } from '../lib/configs/env.js';
import {
	ADMIN_PROJECT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID
} from '../lib/admin/consts.js';

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

const grantable = new Set([
	'AccessToken',
	'AuthorizationCode',
	'RefreshToken',
	'DeviceCode',
	'BackchannelAuthenticationRequest'
]);

for (const name of COLLECTIONS) {
	const col = await db.createCollection(name);
	await col.createIndexes([
		...(grantable.has(name)
			? [
					{
						key: { 'payload.grantId': 1 }
					}
				]
			: []),
		...(name === 'DeviceCode'
			? [
					{
						key: { 'payload.userCode': 1 },
						unique: true
					}
				]
			: []),
		...(name === 'Session'
			? [
					{
						key: { 'payload.uid': 1 },
						unique: true
					}
				]
			: []),
		...(name === 'projects'
			? [
					{
						key: { slug: 1 },
						unique: true
					}
				]
			: []),
		// Signing keys never expire; they are addressed by a unique kid.
		...(name === 'jwks'
			? [
					{
						key: { kid: 1 },
						unique: true
					}
				]
			: [
					{
						key: { expiresAt: 1 },
						expireAfterSeconds: 0
					}
				])
	]);
}

// Provision the initial signing key at schema-creation time so a freshly created database already
// holds a persisted RS256 signing key. The runtime loader (lib/configs/keys.ts) keeps an equivalent
// generate-on-empty fallback for the in-memory adapter and any un-provisioned store.
const jwks = db.collection('jwks');
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
await db.collection('userBuckets').updateOne(
	{ _id: ADMIN_BUCKET_ID },
	{
		$setOnInsert: {
			name: 'Administrators',
			managedBy: [],
			roles: ['super_admin', 'project_admin'],
			authMethods: ['password'],
			createdAt: seedNow,
			updatedAt: seedNow
		}
	},
	{ upsert: true }
);
await db.collection('projects').updateOne(
	{ _id: ADMIN_PROJECT_ID },
	{
		$setOnInsert: {
			name: 'Administration',
			slug: 'admin',
			type: 'admin',
			managedBy: [],
			bucketId: ADMIN_BUCKET_ID,
			createdAt: seedNow,
			updatedAt: seedNow
		}
	},
	{ upsert: true }
);
await db.collection('Client').updateOne(
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

dbClient.close();
