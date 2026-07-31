import { db } from './db.js';
import { type UnnormalizedJWK } from 'lib/configs/verifyJWKs.ts';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { JWKSStoreInstance } from '../types.js';

// Discard storage-only fields so callers only ever see plain JWK objects (contract parity with the
// in-memory adapter). `_id`/`updatedAt` are MongoDB bookkeeping, not part of the JWK.
//
// The cast is the one unavoidable one here: a BSON document is untyped, so nothing but a read can
// tell us what is in it. It claims only that the document is a schema-shaped JWK — not that it is
// normalized — and verifyJWKs is what checks even that, on the way in to the key set.
function toJWK(doc: Record<string, unknown>): UnnormalizedJWK {
	const { _id, updatedAt, ...jwk } = doc;
	return jwk as UnnormalizedJWK;
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
