import { describe, it, expect, beforeEach } from 'bun:test';
import { ProjectStore } from 'lib/adapters/memory/projectStore.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

describe('ProjectStore (memory)', () => {
	let store: ProjectStore;
	beforeEach(() => {
		store = new ProjectStore();
	});

	it('creates and finds a project', async () => {
		const p = await store.create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Acme',
			slug: 'acme'
		});
		expect(p._id).toBeString();
		expect(p.type).toBe('regular');
		expect(await store.find(p._id)).toMatchObject({ slug: 'acme' });
	});

	it('finds by slug and lists by owning group', async () => {
		await store.create({ name: 'Acme', slug: 'acme', ownerGroupId: 'g1' });
		await store.create({ name: 'Globex', slug: 'globex', ownerGroupId: 'g2' });
		expect(await store.findBySlug('globex')).toMatchObject({ name: 'Globex' });
		const mine = await store.listByGroup('g1');
		expect(mine).toHaveLength(1);
		expect(mine[0].slug).toBe('acme');
	});

	it('updates, counts by bucket, and destroys', async () => {
		const p = await store.create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Acme',
			slug: 'acme'
		});
		await store.update(p._id, { bucketId: 'b1' });
		expect(await store.countByBucket('b1')).toBe(1);
		await store.destroy(p._id);
		expect(await store.find(p._id)).toBeNull();
	});

	it('defaults clientIds to [] and updates them', async () => {
		const p = await store.create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'C',
			slug: `c-${Math.random()}`
		});
		expect(p.clientIds).toEqual([]);
		const updated = await store.update(p._id, { clientIds: ['abc'] });
		expect(updated?.clientIds).toEqual(['abc']);
		const reloaded = await store.find(p._id);
		expect(reloaded?.clientIds).toEqual(['abc']);
	});

	// The storage contract for corsOrigins. Both adapters implement the same interface; the mongo
	// store additionally defaults the field on read for documents written before it existed.
	it('defaults corsOrigins to [], accepts them on create, and round-trips an update', async () => {
		const bare = await store.create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Bare',
			slug: `bare-${Math.random()}`
		});
		expect(bare.corsOrigins).toEqual([]);

		const seeded = await store.create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Seeded',
			slug: `seeded-${Math.random()}`,
			corsOrigins: ['https://app.example.com']
		});
		expect(seeded.corsOrigins).toEqual(['https://app.example.com']);
		expect((await store.find(seeded._id))?.corsOrigins).toEqual([
			'https://app.example.com'
		]);

		const updated = await store.update(seeded._id, {
			corsOrigins: ['https://other.example.com', 'https://third.example.com']
		});
		expect(updated?.corsOrigins).toEqual([
			'https://other.example.com',
			'https://third.example.com'
		]);
		expect((await store.find(seeded._id))?.corsOrigins).toEqual([
			'https://other.example.com',
			'https://third.example.com'
		]);

		// Clearing is a first-class operation: an operator revoking browser access must not have to
		// delete the project.
		expect(
			(await store.update(seeded._id, { corsOrigins: [] }))?.corsOrigins
		).toEqual([]);
	});

	it('finds a project by one of its client ids', async () => {
		const store = new ProjectStore();
		const p = await store.create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'FB',
			slug: `fb-${Math.random()}`,
			clientIds: ['cid-123']
		});
		const found = await store.findByClientId('cid-123');
		expect(found?._id).toBe(p._id);
		expect(await store.findByClientId('nope')).toBeNull();
	});
});
