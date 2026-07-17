import { describe, it, expect, beforeEach } from 'bun:test';
import { ProjectStore } from 'lib/adapters/memory/projectStore.ts';

describe('ProjectStore (memory)', () => {
	let store: ProjectStore;
	beforeEach(() => {
		store = new ProjectStore();
	});

	it('creates and finds a project', async () => {
		const p = await store.create({ name: 'Acme', slug: 'acme' });
		expect(p._id).toBeString();
		expect(p.type).toBe('regular');
		expect(await store.find(p._id)).toMatchObject({ slug: 'acme' });
	});

	it('finds by slug and lists by manager', async () => {
		await store.create({ name: 'Acme', slug: 'acme', managedBy: ['u1'] });
		await store.create({ name: 'Globex', slug: 'globex', managedBy: ['u2'] });
		expect(await store.findBySlug('globex')).toMatchObject({ name: 'Globex' });
		const mine = await store.listByManager('u1');
		expect(mine).toHaveLength(1);
		expect(mine[0].slug).toBe('acme');
	});

	it('updates, counts by bucket, and destroys', async () => {
		const p = await store.create({ name: 'Acme', slug: 'acme' });
		await store.update(p._id, { bucketId: 'b1' });
		expect(await store.countByBucket('b1')).toBe(1);
		await store.destroy(p._id);
		expect(await store.find(p._id)).toBeNull();
	});

	it('defaults clientIds to [] and updates them', async () => {
		const p = await store.create({ name: 'C', slug: `c-${Math.random()}` });
		expect(p.clientIds).toEqual([]);
		const updated = await store.update(p._id, { clientIds: ['abc'] });
		expect(updated?.clientIds).toEqual(['abc']);
		const reloaded = await store.find(p._id);
		expect(reloaded?.clientIds).toEqual(['abc']);
	});
});
