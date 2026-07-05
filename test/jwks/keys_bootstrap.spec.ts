import { describe, it, expect } from 'bun:test';

import { resolveKeys } from 'lib/configs/keys.ts';
import { JWKSStore } from 'lib/adapters/memory/jwksStore.ts';

// NOTE: the end-to-end HTTP-layer bootstrap is validated manually via quickstart Scenario A,
// since JWKS_KEYS is a one-time module snapshot. Here we drive resolveKeys directly.
describe('empty-store bootstrap (resolveKeys)', () => {
	it('generates and persists one RS256 signing key on an empty store', async () => {
		const store = new JWKSStore();

		const keys = await resolveKeys(store);

		expect(keys).toHaveLength(1);
		expect(keys[0].kty).toBe('RSA');
		expect(keys[0].alg).toBe('RS256');
		expect(keys[0].use).toBe('sig');

		const stored = await store.getAll();
		expect(stored).toHaveLength(1);
		expect(stored[0].kid).toBe(keys[0].kid);
	});

	it('reuses existing keys on a non-empty store without generating a new one', async () => {
		const store = new JWKSStore();

		const first = await resolveKeys(store);
		const second = await resolveKeys(store);

		expect(second.map((k) => k.kid)).toEqual(first.map((k) => k.kid));
		expect(await store.getAll()).toHaveLength(1);
	});
});
