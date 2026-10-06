import { describe, it, beforeAll, expect } from 'bun:test';

import { adapter } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { STORAGE_INVENTORY } from 'lib/consts/storage_inventory.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { seedAccount } from '../test_helper.js';
import { adminCookie, defaultBucket, setActive } from './fixtures.ts';

/*
 * Enumerated from the running inventory rather than listed here, so an area added later with an account
 * owner is covered the day it is declared — the defect this guards against is the area nobody remembered.
 */
const accountOwned = STORAGE_INVENTORY.flatMap((area) =>
	area.kind === 'model' && area.owners.account !== null
		? [{ name: area.name, field: area.owners.account }]
		: []
);

/**
 * @proves For every storage area the inventory declares account-owned, none of a deactivated user's
 * records remain (spec 069, FR-001, FR-002).
 */
describe('deactivating an end user, across every account-owned storage area', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await defaultBucket();
		cookie = await adminCookie();
	});

	for (const { name, field } of accountOwned) {
		it(`leaves none of the user's ${name} records`, async () => {
			const accountId = nanoid();
			seedAccount(accountId, {}, DEFAULT_BUCKET_ID);
			await adapter(name).upsert(
				nanoid(),
				{ [field]: accountId, exp: epochTime() + 600 },
				600
			);

			const res = await setActive(cookie, accountId, false);

			expect(res.status).toBe(200);
			expect(await adapter(name).findByOwner(field, accountId)).toEqual([]);
		});
	}
});
