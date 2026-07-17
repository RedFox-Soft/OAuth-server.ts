import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProjectStore, getBucketStore } from 'lib/adapters/index.ts';
import {
	ADMIN_PROJECT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID
} from 'lib/admin/consts.ts';
import { Client } from 'lib/models/client.ts';

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
});
