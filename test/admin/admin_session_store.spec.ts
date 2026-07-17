import { describe, it, expect, beforeEach } from 'bun:test';
import { AdminSessionStore } from 'lib/adapters/memory/adminSessionStore.ts';

describe('AdminSessionStore (memory)', () => {
	let store: AdminSessionStore;
	beforeEach(() => {
		store = new AdminSessionStore();
	});

	it('creates, finds, touches and destroys', async () => {
		const s = await store.create({
			userId: 'u1',
			bucketId: 'admin',
			tokens: { idToken: 'x' },
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});
		expect(await store.find(s._id)).toMatchObject({ userId: 'u1' });
		const before = (await store.find(s._id))!.expiresAt.getTime();
		await store.touch(s._id, 120);
		expect((await store.find(s._id))!.expiresAt.getTime()).toBeGreaterThan(
			before
		);
		await store.destroy(s._id);
		expect(await store.find(s._id)).toBeNull();
	});

	it('returns null for an expired session', async () => {
		const s = await store.create({
			userId: 'u1',
			bucketId: 'admin',
			tokens: {},
			ttlSeconds: -1,
			absoluteTtlSeconds: 3600
		});
		expect(await store.find(s._id)).toBeNull();
	});
});
