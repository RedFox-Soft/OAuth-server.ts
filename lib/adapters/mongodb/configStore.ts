import crypto from 'crypto';
import { ObjectId } from 'mongodb';
import { db } from './db.js';

function stringTo24CharHex(str: string) {
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
