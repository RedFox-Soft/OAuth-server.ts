import { describe, it, expect, beforeEach } from 'bun:test';
import { UserBucketStore } from 'lib/adapters/memory/userBucketStore.ts';

describe('UserBucketStore (memory)', () => {
	let store: UserBucketStore;
	beforeEach(() => {
		store = new UserBucketStore();
	});

	it('creates with default sign-in settings and finds', async () => {
		const b = await store.create({ name: 'Dev users', managedBy: ['u1'] });
		// Replaces the former `authMethods: ['password']` assertion. `passwordLogin` must default true and
		// not merely be absent: it is read as a boolean, and undefined would close the password door.
		expect(b.passwordLogin).toBe(true);
		expect(b.federation).toEqual([]);
		expect(await store.find(b._id)).toMatchObject({ name: 'Dev users' });
	});

	it('lists by manager and updates roles', async () => {
		const b = await store.create({ name: 'Dev', managedBy: ['u1'] });
		expect(await store.listByManager('u1')).toHaveLength(1);
		await store.update(b._id, { roles: ['viewer', 'editor'] });
		expect((await store.find(b._id))?.roles).toEqual(['viewer', 'editor']);
	});
});
