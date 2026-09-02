import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getBucketStore,
	getGroupStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	ADMIN_PROJECT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID
} from 'lib/admin/consts.ts';
import { Client } from 'lib/models/client.ts';
import { UNASSIGNED_GROUP_ID, SYSTEM_GROUP_NAME } from 'lib/admin/consts.ts';

describe('ensureAdminSeed', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
	});

	it('is idempotent and seeds admin project + bucket + client', async () => {
		await ensureAdminSeed();
		await ensureAdminSeed();

		const project = await getProjectStore().find(ADMIN_PROJECT_ID);
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);

		expect(project).toMatchObject({ type: 'admin', bucketId: ADMIN_BUCKET_ID });
		expect(bucket?.roles).toEqual(['super_admin', 'project_admin']);

		const client = await Client.find(ADMIN_CLIENT_ID);
		expect(client).toBeTruthy();
		expect(client.tokenEndpointAuthMethod).toBe('none');
	});

	it('seeds the admin project with the panel client id', async () => {
		await ensureAdminSeed();
		const project = await getProjectStore().find(ADMIN_PROJECT_ID);
		expect(project?.clientIds).toContain(ADMIN_CLIENT_ID);
	});

	it('backfills clientIds on an admin project that predates the field', async () => {
		resetAdminMemoryStores();
		const store = getProjectStore();
		const p = await store.create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			_id: ADMIN_PROJECT_ID,
			name: 'Administration',
			slug: 'admin',
			type: 'admin',
			bucketId: ADMIN_BUCKET_ID
		});
		// Simulate a legacy document created before clientIds existed.
		delete (p as { clientIds?: string[] }).clientIds;
		await ensureAdminSeed();
		const reloaded = await store.find(ADMIN_PROJECT_ID);
		expect(reloaded?.clientIds).toContain(ADMIN_CLIENT_ID);
	});

	/*
	 * The holding group everything else in the seed is given as its owner, asserted here because nothing
	 * else did: its name is what the console shows a super administrator, and it is one of the pair of
	 * values that has to stay in step with database/mongodb.ts.
	 */
	it('seeds the reserved holding group under the shared system name', async () => {
		await ensureAdminSeed();
		const group = await getGroupStore().find(UNASSIGNED_GROUP_ID);
		expect(group).toMatchObject({
			kind: 'system',
			name: SYSTEM_GROUP_NAME,
			members: []
		});
	});

	it('seeds a manageable default (redfox) bucket', async () => {
		await ensureAdminSeed();
		const bucket = await getBucketStore().find('redfox');
		expect(bucket?.name).toBe('Default users');
		// Was `authMethods: ['password']`. The seeded default bucket must remain signable-into by password
		// and hold no upstream providers — the shape every deployment starts from.
		expect(bucket?.passwordLogin).toBe(true);
		expect(bucket?.federation).toEqual([]);
	});
});
