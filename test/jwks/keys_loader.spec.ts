import { describe, it, expect } from 'bun:test';

import { resolveKeys } from 'lib/configs/keys.ts';
import { JWKSStore } from 'lib/adapters/memory/jwksStore.ts';
import { type JWKS } from 'lib/configs/verifyJWKs.ts';
import { testSigningKeys } from './fixtures.js';

describe('resolveKeys (populated store + validation)', () => {
	it('returns the validated keys from a populated store', async () => {
		const store = new JWKSStore();
		for (const key of testSigningKeys) {
			await store.set(key.kid, key);
		}

		const keys = await resolveKeys(store);
		expect(keys.map((k) => k.kid).sort()).toEqual(
			testSigningKeys.map((k) => k.kid).sort()
		);
	});

	it('throws on an invalid stored key (fail fast)', async () => {
		const store = new JWKSStore();
		// RSA key missing the required modulus `n` — must fail key-set validation.
		const invalid = {
			kty: 'RSA',
			kid: 'invalid-rsa',
			use: 'sig',
			alg: 'RS256',
			e: 'AQAB'
		} as unknown as JWKS;
		await store.set(invalid.kid, invalid);

		expect(resolveKeys(store)).rejects.toThrow();
	});
});
