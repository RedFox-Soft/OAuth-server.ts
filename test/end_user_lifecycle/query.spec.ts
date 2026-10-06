import { describe, it, beforeAll, expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.ts';
import { MAX_END_USER_PAGE } from 'lib/adapters/types.ts';
import { createEndUser, type EndUserActor } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';
import { defaultBucket } from './fixtures.ts';

/*
 * Against the store, because no public surface reads users by these keys until provisioning arrives (spec 069
 * part 2) — the lookups a provisioning client makes before it creates anyone.
 */

async function provision(
	bucketId: string,
	actor: EndUserActor,
	fields: { userName?: string; externalId?: string } = {}
) {
	const bucket = await defaultBucket();
	return createEndUser(
		{ ...bucket, _id: bucketId },
		actor,
		{ id: nanoid(), email: `${nanoid()}@x.io`, ...fields },
		async () => {}
	);
}

/**
 * @proves Users can be found by their provisioned identity, and a lookup scoped to one connection
 * sees nobody else's users (spec 069, FR-016, FR-017).
 */
describe('finding users in a bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('finds a user by username in any letter case', async () => {
		const bucketId = `q-${nanoid()}`;
		const user = await provision(
			bucketId,
			{ kind: 'admin' },
			{
				userName: 'Katherine.Johnson'
			}
		);

		const { users } = await getUserStore(bucketId).query(
			{ userName: 'KATHERINE.JOHNSON' },
			{ startIndex: 1, count: 10 }
		);

		expect(users.map((u) => u._id)).toEqual([user._id]);
	});

	it('returns none of another connection’s users or local users when scoped to one connection', async () => {
		const bucketId = `q-${nanoid()}`;
		const mine = await provision(bucketId, {
			kind: 'connection',
			connectionId: 'conn-a'
		});
		await provision(bucketId, { kind: 'connection', connectionId: 'conn-b' });
		await provision(bucketId, { kind: 'admin' });

		const { users, totalResults } = await getUserStore(bucketId).query(
			{ provisionedBy: 'conn-a' },
			{ startIndex: 1, count: 10 }
		);

		expect(users.map((u) => u._id)).toEqual([mine._id]);
		expect(totalResults).toBe(1);
	});

	it('returns at most the page maximum when asked for more', async () => {
		const bucketId = `q-${nanoid()}`;
		const store = getUserStore(bucketId);
		for (let i = 0; i <= MAX_END_USER_PAGE; i += 1) {
			await store.create(`${i}-${nanoid()}@x.io`, 'hash', [], true);
		}

		const { users, totalResults } = await store.query(
			{},
			{ startIndex: 1, count: MAX_END_USER_PAGE + 500 }
		);

		expect(users).toHaveLength(MAX_END_USER_PAGE);
		expect(totalResults).toBe(MAX_END_USER_PAGE + 1);
	});
});
