import { describe, it, beforeAll, expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';

/*
 * The users search against the store, the contract all three backends answer: the console and the agent reach
 * it through the list route (test/admin/users_list.spec.ts), and database/verify_end_user_identity.ts asks a
 * real MongoDB and PostgreSQL the same questions.
 */

const PAGE = { startIndex: 1, count: 50 };

async function bucketHolding(...emails: string[]) {
	const store = getUserStore(`search-${nanoid()}`);
	const ids: Record<string, string> = {};
	for (const email of emails) {
		ids[email] = (await store.create(email, 'hash', true))._id;
	}
	return { store, ids };
}

/**
 * @proves A support administrator finds a person by the start of their email or username in any letter case,
 * or by their exact id, and a search is taken literally rather than as a pattern.
 */
describe('searching a bucket for a person', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('finds a person by the start of their email in another letter case', async () => {
		const { store, ids } = await bucketHolding(
			'Alice.Smith@example.com',
			'bob@example.com'
		);

		const { users } = await store.query({ search: 'ALI' }, PAGE);

		expect(users.map((u) => u._id)).toEqual([ids['Alice.Smith@example.com']]);
	});

	it('finds a person by the start of their username in another letter case', async () => {
		const { store, ids } = await bucketHolding('a@example.com');
		await store.update(ids['a@example.com'], { userName: 'Grace.Hopper' });

		const { users } = await store.query({ search: 'grace.h' }, PAGE);

		expect(users.map((u) => u._id)).toEqual([ids['a@example.com']]);
	});

	it('finds a person by their exact id', async () => {
		const { store, ids } = await bucketHolding('id@example.com');
		const id = ids['id@example.com'];

		const { users } = await store.query({ search: id }, PAGE);

		expect(users.map((u) => u._id)).toEqual([id]);
	});

	it('does not find a person by the start of their id', async () => {
		const { store, ids } = await bucketHolding('partial@example.com');

		const { users } = await store.query(
			{ search: ids['partial@example.com'].slice(0, 6) },
			PAGE
		);

		expect(users).toEqual([]);
	});

	it('takes a percent sign literally rather than as a wildcard', async () => {
		const { store, ids } = await bucketHolding(
			'100%off@example.com',
			'100xoff@example.com'
		);

		const { users } = await store.query({ search: '100%' }, PAGE);

		expect(users.map((u) => u._id)).toEqual([ids['100%off@example.com']]);
	});

	it('takes an underscore and a dot literally', async () => {
		const { store, ids } = await bucketHolding(
			'a_b.c@example.com',
			'axbxc@example.com'
		);

		const { users } = await store.query({ search: 'a_b.' }, PAGE);

		expect(users.map((u) => u._id)).toEqual([ids['a_b.c@example.com']]);
	});

	it('pages in email order with the total of every match', async () => {
		const { store } = await bucketHolding(
			'carol@example.com',
			'ann@example.com',
			'bea@example.com'
		);

		const first = await store.query({}, { startIndex: 1, count: 2 }, 'email');
		const second = await store.query({}, { startIndex: 3, count: 2 }, 'email');

		expect(first.users.map((u) => u.email)).toEqual([
			'ann@example.com',
			'bea@example.com'
		]);
		expect(second.users.map((u) => u.email)).toEqual(['carol@example.com']);
		expect(first.totalResults).toBe(3);
	});
});
