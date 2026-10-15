import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getGroupStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_CLIENT_ID } from 'lib/admin/consts.ts';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.ts';
import { DEFAULT_REQUEST_BUCKET } from 'lib/configs/issuer.ts';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { Client } from 'lib/models/client.ts';
import { UNASSIGNED_GROUP_ID, SYSTEM_GROUP_NAME } from 'lib/admin/consts.ts';

/**
 * @proves Provisioning is idempotent and leaves an instance with a working administrators' bucket,
 * console and agent clients that sign in there, and a default bucket.
 */
describe('ensureAdminSeed', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
	});

	it('is idempotent and seeds the administrators bucket and the console client', async () => {
		await ensureAdminSeed();
		await ensureAdminSeed();

		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);

		expect(bucket?._id).toBe(ADMIN_BUCKET_ID);

		const client = await Client.find(ADMIN_CLIENT_ID);
		expect(client).toBeTruthy();
		expect(client.tokenEndpointAuthMethod).toBe('none');
	});

	/*
	 * The agent client has no rule of its own, as the console client does: it signs administrators in only
	 * because the seed puts it in their bucket. Outside it, it would fall through to the default bucket.
	 */
	it('seeds the agent client so that it signs in to the administrators bucket', async () => {
		await ensureAdminSeed();

		expect(
			await resolveBucketForRequest(
				ADMIN_MCP_CLIENT_ID,
				undefined,
				DEFAULT_REQUEST_BUCKET
			)
		).toBe(ADMIN_BUCKET_ID);
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
