import { describe, it, beforeEach, expect } from 'bun:test';

import { JWKSStore } from 'lib/adapters/memory/jwksStore.ts';
import { testSigningKeys } from './fixtures.js';

const [rsaKey, ecKey] = testSigningKeys;

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

	it('getAll returns every stored JWK', async () => {
		await store.set(rsaKey.kid, rsaKey);
		await store.set(ecKey.kid, ecKey);

		const all = await store.getAll();
		expect(all).toHaveLength(2);
		expect(all).toEqual(expect.arrayContaining([rsaKey, ecKey]));
	});

	it('set is an idempotent upsert by kid', async () => {
		await store.set(rsaKey.kid, rsaKey);
		await store.set(rsaKey.kid, rsaKey);

		expect(await store.getAll()).toHaveLength(1);
	});

	it('delete removes a key by kid', async () => {
		await store.set(rsaKey.kid, rsaKey);
		await store.delete(rsaKey.kid);

		expect(await store.get(rsaKey.kid)).toBeNull();
		expect(await store.getAll()).toEqual([]);
	});
});
