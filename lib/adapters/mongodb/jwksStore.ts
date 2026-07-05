import { db } from './db.js';
import { type JWKS } from 'lib/configs/verifyJWKs.ts';
import type { JWKSStoreInstance } from '../types.js';

// Discard storage-only fields so callers only ever see plain JWK objects (contract parity with the
// in-memory adapter). `_id`/`updatedAt` are MongoDB bookkeeping, not part of the JWK.
function toJWK(doc: Record<string, unknown>): JWKS {
	const { _id, updatedAt, ...jwk } = doc;
	// The stored document is a JWK plus bookkeeping; after stripping it is a JWKS by construction.
	return jwk as JWKS;
}

export class JWKSStore implements JWKSStoreInstance {
	private collectionName = 'jwks';

	async get(keyId: string): Promise<JWKS | null> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ kid: keyId });
		return result ? toJWK(result) : null;
	}

	async set(keyId: string, key: JWKS): Promise<void> {
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

	async getAll(): Promise<JWKS[]> {
		const result = await db.collection(this.collectionName).find({}).toArray();
		return result.map(toJWK);
	}
}
