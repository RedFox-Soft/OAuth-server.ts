import { type UnnormalizedJWK } from 'lib/configs/verifyJWKs.ts';
import type { JWKSStoreInstance } from '../types.js';

export class JWKSStore implements JWKSStoreInstance {
	private keys = new Map<string, UnnormalizedJWK>();

	async get(keyId: string): Promise<UnnormalizedJWK | null> {
		return this.keys.get(keyId) || null;
	}

	async set(keyId: string, key: UnnormalizedJWK): Promise<void> {
		this.keys.set(keyId, key);
	}

	async delete(keyId: string): Promise<void> {
		this.keys.delete(keyId);
	}

	async getAll(): Promise<UnnormalizedJWK[]> {
		return Array.from(this.keys.values());
	}
}
