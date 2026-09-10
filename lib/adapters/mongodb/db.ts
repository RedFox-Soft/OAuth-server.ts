import { MongoClient, ServerApiVersion } from 'mongodb';

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

export const db = (await dbClient.connect()).db(process.env.DATABASE_NAME);

/*
 * The reachability probe behind the startup check and the readiness endpoint. Reads and writes
 * nothing, so it can neither be affected by application data nor affect it.
 */
export async function ping(): Promise<void> {
	await db.command({ ping: 1 });
}
