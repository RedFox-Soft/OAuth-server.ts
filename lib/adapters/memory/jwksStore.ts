import { type JWKS } from 'lib/configs/verifyJWKs.ts';
import type { JWKSStoreInstance } from '../types.js';

export class JWKSStore implements JWKSStoreInstance {
	private keys = new Map<string, Record<string, JWKS>>();

	async get(keyId: string): Promise<Record<string, JWKS> | null> {
		return this.keys.get(keyId) || null;
	}

	async set(keyId: string, key: Record<string, JWKS>): Promise<void> {
		this.keys.set(keyId, key);
	}

	async delete(keyId: string): Promise<void> {
		this.keys.delete(keyId);
	}

	async getAll(): Promise<Array<Record<string, JWKS>>> {
		return Array.from(this.keys.values());
	}
}
