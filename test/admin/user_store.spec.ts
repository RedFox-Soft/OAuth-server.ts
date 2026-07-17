import { describe, it, expect, beforeEach } from 'bun:test';
import { UserStore } from 'lib/adapters/memory/userStore.ts';

describe('UserStore (memory) roles', () => {
	let store: UserStore;
	beforeEach(() => {
		store = new UserStore('admin');
	});

	it('creates a user with roles and returns it', async () => {
		const u = await store.create('a@x.io', 'hash', ['super_admin']);
		expect(u.roles).toEqual(['super_admin']);
		expect(u._id).toBeString();
	});

	it('lists users and updates roles', async () => {
		await store.create('a@x.io', 'hash', ['super_admin']);
		const u = await store.create('b@x.io', 'hash');
		expect(await store.list()).toHaveLength(2);
		await store.update(u._id, { roles: ['project_admin'] });
		expect((await store.find(u._id))?.roles).toEqual(['project_admin']);
	});
});
