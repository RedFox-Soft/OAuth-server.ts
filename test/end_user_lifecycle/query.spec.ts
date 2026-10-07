import { describe, it, beforeAll, expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.ts';
import { MAX_END_USER_PAGE } from 'lib/adapters/types.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';

/*
 * The page bound, against the store: the SCIM surface caps `count` before the store sees it, so this is the
 * only place the store's own clamp is observable. The lookups by username and by connection that used to live
 * here are proved at the SCIM surface now (test/scim/users_lifecycle.spec.ts, test/scim/isolation.spec.ts).
 */

/**
 * @proves A page of users never exceeds the page maximum, however many are asked for (spec 069, FR-017).
 */
describe('finding users in a bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('returns at most the page maximum when asked for more', async () => {
		const bucketId = `q-${nanoid()}`;
		const store = getUserStore(bucketId);
		for (let i = 0; i <= MAX_END_USER_PAGE; i += 1) {
			await store.create(`${i}-${nanoid()}@x.io`, 'hash', true);
		}

		const { users, totalResults } = await store.query(
			{},
			{ startIndex: 1, count: MAX_END_USER_PAGE + 500 }
		);

		expect(users).toHaveLength(MAX_END_USER_PAGE);
		expect(totalResults).toBe(MAX_END_USER_PAGE + 1);
	});
});
