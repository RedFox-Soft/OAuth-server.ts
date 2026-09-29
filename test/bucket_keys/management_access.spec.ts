import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { administrator, call, ownedBucket } from './keys_admin.ts';

/**
 * @proves A bucket's keys are managed by its owning group's administrators and by super
 * administrators, by nobody else, and never through the bucket routes for a bucket that signs with the
 * instance keys — which stay a super administrator's alone.
 */
describe('who may manage a bucket key', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'bucket_keys' });
		await ensureAdminSeed();
	});

	it('refuses another group administrator listing the keys', async () => {
		const owner = await administrator(['project_admin']);
		const outsider = await administrator(['project_admin']);
		const bucket = await ownedBucket(owner.groupId);

		const res = await call(
			'GET',
			`/admin/api/buckets/${bucket._id}/keys`,
			outsider.cookie
		);

		expect(res.status).toBe(403);
	});

	it('refuses another group administrator generating a key', async () => {
		const owner = await administrator(['project_admin']);
		const outsider = await administrator(['project_admin']);
		const bucket = await ownedBucket(owner.groupId);

		const res = await call(
			'POST',
			`/admin/api/buckets/${bucket._id}/keys`,
			outsider.cookie,
			{ alg: 'ES256' }
		);

		expect(res.status).toBe(403);
	});

	it('refuses a group administrator the instance key set', async () => {
		const { cookie } = await administrator(['project_admin']);

		const res = await call('POST', '/admin/api/jwks', cookie, { alg: 'ES256' });

		expect(res.status).toBe(403);
	});

	it('refuses the bucket routes for a bucket that signs with the instance keys', async () => {
		const { cookie } = await administrator(['super_admin']);

		const res = await call(
			'POST',
			`/admin/api/buckets/${DEFAULT_BUCKET_ID}/keys`,
			cookie,
			{ alg: 'ES256' }
		);

		expect(res.status).toBe(409);
	});

	it('lets a super administrator generate a key for a bucket of any group', async () => {
		const owner = await administrator(['project_admin']);
		const { cookie } = await administrator(['super_admin']);
		const bucket = await ownedBucket(owner.groupId);

		const res = await call(
			'POST',
			`/admin/api/buckets/${bucket._id}/keys`,
			cookie,
			{ alg: 'ES256' }
		);

		expect(res.status).toBe(201);
	});
});
