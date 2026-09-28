import { describe, it, expect, beforeEach } from 'bun:test';
import { AdminSessionStore } from 'lib/adapters/memory/adminSessionStore.ts';
import { present } from 'test/shape.js';

/**
 * @proves A console session survives a read, is extended by activity, is gone after logout, and
 * is refused once it has expired.
 */
describe('AdminSessionStore (memory)', () => {
	let store: AdminSessionStore;
	beforeEach(() => {
		store = new AdminSessionStore();
	});

	it('a console session survives a read, is extended by activity, and is gone after logout', async () => {
		const s = await store.create({
			userId: 'u1',
			bucketId: 'admin',
			activeGroupId: 'g1',
			tokens: { idToken: 'x' },
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});
		expect(await store.find(s._id)).toMatchObject({ userId: 'u1' });
		const before = present(
			await store.find(s._id),
			'(await store.find(s._id))'
		).expiresAt.getTime();
		await store.touch(s._id, 120);
		expect(
			present(
				await store.find(s._id),
				'(await store.find(s._id))'
			).expiresAt.getTime()
		).toBeGreaterThan(before);
		await store.destroy(s._id);
		expect(await store.find(s._id)).toBeNull();
	});

	it('returns null for an expired session', async () => {
		const s = await store.create({
			userId: 'u1',
			bucketId: 'admin',
			activeGroupId: 'g1',
			tokens: {},
			ttlSeconds: -1,
			absoluteTtlSeconds: 3600
		});
		expect(await store.find(s._id)).toBeNull();
	});
});
