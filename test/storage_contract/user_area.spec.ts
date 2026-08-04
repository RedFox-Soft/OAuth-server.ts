import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';

// Storage contract for destroying a bucket's end-user area —
// specs/019-deletion-integrity/contracts/storage-adapter.md, clauses C15..C16.
//
// On MongoDB this drops the `user_<bucket>` collection, which is what closes the
// left-behind-collection hole. In memory there is no collection to drop, but it is deliberately not a
// no-op: a bucket re-created under the same id must not inherit its predecessor's users.

describe('storage contract: destroyArea', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('leaves the area holding nothing (C15)', async () => {
		const store = getUserStore('area-c15');
		await store.create('one@example.com', 'hashed');
		await store.create('two@example.com', 'hashed');
		expect((await store.list()).length).toBe(2);

		await store.destroyArea();

		expect(await store.list()).toEqual([]);
	});

	it('a store re-created for the same bucket id starts empty (C16)', async () => {
		const store = getUserStore('area-c16');
		const created = await store.create('gone@example.com', 'hashed');
		await store.destroyArea();

		// Drops the cached per-area store singletons, so this is a genuinely fresh store for the id.
		resetAdminMemoryStores();
		const reborn = getUserStore('area-c16');

		expect(await reborn.list()).toEqual([]);
		expect(await reborn.find(created._id)).toBeNull();
	});
});
