import { describe, it, expect, beforeEach } from 'bun:test';
import { resolveBucketForClient } from 'lib/admin/auth/resolveBucket.ts';
import { getProjectStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_CLIENT_ID, ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

describe('resolveBucketForClient', () => {
	beforeEach(() => {
		resetAdminMemoryStores();
	});

	it('routes the admin client to the admin bucket', async () => {
		expect(await resolveBucketForClient(ADMIN_CLIENT_ID)).toBe(ADMIN_BUCKET_ID);
	});

	it('routes an assigned client to its project bucket', async () => {
		await getProjectStore().create({
			name: 'P',
			slug: `p-${Math.random()}`,
			bucketId: 'devs',
			clientIds: ['app-1']
		});
		expect(await resolveBucketForClient('app-1')).toBe('devs');
	});

	it('falls back to redfox for an unassigned or missing client', async () => {
		expect(await resolveBucketForClient('unknown')).toBe('redfox');
		expect(await resolveBucketForClient(undefined)).toBe('redfox');
	});
});
