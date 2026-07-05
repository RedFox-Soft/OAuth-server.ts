import { type JWKS } from 'lib/configs/verifyJWKs.ts';
import type { JWKSStoreInstance } from '../types.js';

export class JWKSStore implements JWKSStoreInstance {
	private keys = new Map<string, JWKS>();

	async get(keyId: string): Promise<JWKS | null> {
		return this.keys.get(keyId) || null;
	}

	async set(keyId: string, key: JWKS): Promise<void> {
		this.keys.set(keyId, key);
	}

	async delete(keyId: string): Promise<void> {
		this.keys.delete(keyId);
	}

	async getAll(): Promise<JWKS[]> {
		return Array.from(this.keys.values());
	}
}
