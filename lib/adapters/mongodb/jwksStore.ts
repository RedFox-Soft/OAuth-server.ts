import { db } from './db.js';
import { type JWKS } from 'lib/configs/verifyJWKs.ts';
import type { JWKSStoreInstance } from '../types.js';

export class JWKSStore implements JWKSStoreInstance {
	private collectionName = 'jwks';

	async get(keyId: string): Promise<Record<string, JWKS> | null> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ kid: keyId });
		return result || null;
	}

	async set(keyId: string, key: Record<string, JWKS>): Promise<void> {
		await db
			.collection(this.collectionName)
			.updateOne(
				{ kid: keyId },
				{ $set: { kid: keyId, key, updatedAt: new Date() } },
				{ upsert: true }
			);
	}

	async delete(keyId: string): Promise<void> {
		await db.collection(this.collectionName).deleteOne({ kid: keyId });
	}

	async getAll(): Promise<Array<Record<string, JWKS>>> {
		const result = await db.collection(this.collectionName).find({}).toArray();
		return result;
	}
}
