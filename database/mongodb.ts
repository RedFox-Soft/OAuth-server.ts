import { MongoClient, ServerApiVersion } from 'mongodb';
import { COLLECTIONS } from './collections';
import { generateJWKS } from '../lib/helpers/jwks.js';

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

dbClient.close();
