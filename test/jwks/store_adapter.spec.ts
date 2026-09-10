import { describe, it, beforeEach, expect } from 'bun:test';

import { JWKSStore } from 'lib/adapters/memory/jwksStore.ts';
import { testSigningKeys } from './fixtures.js';

const [rsaKey, ecKey] = testSigningKeys;

/**
 * @proves A key round-trips through the store as a plain JWK, is loaded in full at boot, and a
 * deleted key stops being published or used.
 */
describe('jwksStore adapter contract (memory)', () => {
	let store: JWKSStore;

	beforeEach(() => {
		store = new JWKSStore();
	});

	it('returns an empty array for an empty store', async () => {
		expect(await store.getAll()).toEqual([]);
	});

	it('returns null when getting an unknown kid', async () => {
		expect(await store.get('does-not-exist')).toBeNull();
	});

	it('round-trips a plain JWK object (no envelope, no _id)', async () => {
		await store.set(rsaKey.kid, rsaKey);

		const got = await store.get(rsaKey.kid);
		expect(got).toEqual(rsaKey);
		// Contract: stored/returned unit is the JWK itself, not a wrapper document.
		expect(got).not.toHaveProperty('key');
		expect(got).not.toHaveProperty('_id');
		expect(got).not.toHaveProperty('updatedAt');
	});

	it('every stored key is loaded at boot', async () => {
		await store.set(rsaKey.kid, rsaKey);
		await store.set(ecKey.kid, ecKey);

		const all = await store.getAll();
		expect(all).toHaveLength(2);
		expect(all).toEqual(expect.arrayContaining([rsaKey, ecKey]));
	});

	it('storing a key twice leaves one key', async () => {
		await store.set(rsaKey.kid, rsaKey);
		await store.set(rsaKey.kid, rsaKey);

		expect(await store.getAll()).toHaveLength(1);
	});

	it('a deleted key is no longer published or used for signing', async () => {
		await store.set(rsaKey.kid, rsaKey);
		await store.delete(rsaKey.kid);

		expect(await store.get(rsaKey.kid)).toBeNull();
		expect(await store.getAll()).toEqual([]);
	});
});
