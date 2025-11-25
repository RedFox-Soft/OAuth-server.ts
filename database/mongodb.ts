import { MongoClient, ServerApiVersion } from 'mongodb';
import { COLLECTIONS } from './collections';

if (!process.env.MONGODB_URI) {
	throw new Error('MONGODB_URI must be provided as an env var');
}

const options = {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true
	}
};

const dbClient = new MongoClient(process.env.MONGODB_URI, options);
const db = (await dbClient.connect()).db();

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
		{
			key: { expiresAt: 1 },
			expireAfterSeconds: 0
		}
	]);
}
