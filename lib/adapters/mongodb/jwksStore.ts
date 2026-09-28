import type { Document } from 'mongodb';
import { db } from './db.js';
import { StoredJWK, type UnnormalizedJWK } from 'lib/configs/verifyJWKs.ts';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import type { JWKSStoreInstance } from '../types.js';

// Discard storage-only fields so callers only ever see plain JWK objects (contract parity with the
// in-memory adapter). `_id`/`updatedAt` are MongoDB bookkeeping, not part of the JWK — and must go
// before the check, since every key schema refuses a member it does not declare.
function toJWK(doc: Document): UnnormalizedJWK {
	const { _id, updatedAt, ...jwk } = doc;
	return documentOf(STORE_AREAS.jwks, StoredJWK, jwk);
}

export class JWKSStore implements JWKSStoreInstance {
	private collectionName: string = STORE_AREAS.jwks;

	async get(keyId: string): Promise<UnnormalizedJWK | null> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ kid: keyId });
		return result ? toJWK(result) : null;
	}

	async set(keyId: string, key: UnnormalizedJWK): Promise<void> {
		await db
			.collection(this.collectionName)
			.updateOne(
				{ kid: keyId },
				{ $set: { ...key, kid: keyId, updatedAt: new Date() } },
				{ upsert: true }
			);
	}

	async delete(keyId: string): Promise<void> {
		await db.collection(this.collectionName).deleteOne({ kid: keyId });
	}

	async getAll(): Promise<UnnormalizedJWK[]> {
		const result = await db.collection(this.collectionName).find({}).toArray();
		return result.map(toJWK);
	}
}
