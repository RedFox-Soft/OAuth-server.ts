import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import crypto from 'crypto';

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

function stringTo24CharHex(str: string) {
	// Use SHA-256 and take the first 12 bytes (24 hex characters)
	const hash = crypto.createHash('sha256').update(str).digest('hex');
	return hash.substring(0, 24);
}

class ConfigStore {
	static instance = new ConfigStore();
	private collectionName = 'serviceConfig';
	private configId = new ObjectId(stringTo24CharHex('appConfig'));

	async get(): Promise<Record<string, unknown> | null> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ _id: this.configId });
		return result?.config || null;
	}

	async set(config: Record<string, unknown>): Promise<void> {
		await db
			.collection(this.collectionName)
			.updateOne(
				{ _id: this.configId },
				{ $set: { config, updatedAt: new Date() } },
				{ upsert: true }
			);
	}
}

export const configStore = ConfigStore.instance;

export class MongoAdapter {
	name: string;

	constructor(name: string) {
		this.name = name;
	}

	async upsert(_id: string, payload: Record<string, any>, expiresIn: number) {
		let expiresAt!: Date;

		if (expiresIn) {
			expiresAt = new Date(Date.now() + expiresIn * 1000);
		}

		await this.coll().updateOne(
			{ _id },
			{ $set: { payload, ...(expiresAt ? { expiresAt } : undefined) } },
			{ upsert: true }
		);
	}

	async find(_id: string) {
		const result = await this.coll().findOne(
			{ _id },
			{ projection: { payload: 1 } }
		);

		if (!result) return;
		return result.payload;
	}

	async findByUserCode(userCode: string) {
		const result = await this.coll().findOne(
			{ 'payload.userCode': userCode },
			{ projection: { payload: 1 } }
		);

		if (!result) return;
		return result.payload;
	}

	async findByUid(uid: string) {
		const result = await this.coll().findOne(
			{ 'payload.uid': uid },
			{ projection: { payload: 1 } }
		);

		if (!result) return;
		return result.payload;
	}

	async destroy(_id: string) {
		await this.coll().deleteOne({ _id });
	}

	async revokeByGrantId(grantId: string) {
		await this.coll().deleteMany({ 'payload.grantId': grantId });
	}

	async consume(_id: string) {
		await this.coll().findOneAndUpdate(
			{ _id },
			{ $set: { 'payload.consumed': Math.floor(Date.now() / 1000) } }
		);
	}

	coll(name: string = this.name) {
		return db.collection<{ _id: string; payload: Record<string, any> }>(name);
	}
}
