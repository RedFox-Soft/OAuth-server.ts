import { describe, it, expect, beforeEach } from 'bun:test';
import { UserBucketStore } from 'lib/adapters/memory/userBucketStore.ts';

describe('UserBucketStore (memory)', () => {
	let store: UserBucketStore;
	beforeEach(() => {
		store = new UserBucketStore();
	});

	it('creates with default authMethods and finds', async () => {
		const b = await store.create({ name: 'Dev users', managedBy: ['u1'] });
		expect(b.authMethods).toEqual(['password']);
		expect(await store.find(b._id)).toMatchObject({ name: 'Dev users' });
	});

	it('lists by manager and updates roles', async () => {
		const b = await store.create({ name: 'Dev', managedBy: ['u1'] });
		expect(await store.listByManager('u1')).toHaveLength(1);
		await store.update(b._id, { roles: ['viewer', 'editor'] });
		expect((await store.find(b._id))?.roles).toEqual(['viewer', 'editor']);
	});
});
