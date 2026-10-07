import { describe, it, expect, beforeEach } from 'bun:test';
import { UserStore } from 'lib/adapters/memory/userStore.ts';

/**
 * @proves End-user records are listed from the store, and a deletion actually removes one.
 */
describe('UserStore (memory)', () => {
	let store: UserStore;
	beforeEach(() => {
		store = new UserStore('admin');
	});

	it('lists users', async () => {
		await store.create('a@x.io', 'hash');
		await store.create('b@x.io', 'hash');
		expect(await store.list()).toHaveLength(2);
	});

	it('hard-deletes a user', async () => {
		const u = await store.create('del@x.io', 'hash');
		expect(await store.find(u._id)).not.toBeNull();
		await store.destroy(u._id);
		expect(await store.find(u._id)).toBeNull();
	});
});
