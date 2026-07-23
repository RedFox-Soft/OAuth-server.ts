import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	adminAuditStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { UserBucket } from 'lib/adapters/types.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`su-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

describe('bucket verification settings API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('defaults new buckets to open + verification off', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: 'Defaults' },
			{ headers: { cookie } }
		);
		const bucket = res.data as UserBucket;
		expect(bucket.registrationOpen).toBe(true);
		expect(bucket.emailVerificationRequired).toBe(false);
		expect(bucket.verificationMethod).toBe('link');
	});

	it('persists a settings patch and records an audit entry', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'Settable' },
			{ headers: { cookie } }
		);
		const bucket = created.data as UserBucket;
		const patched = await client.admin.api.buckets({ id: bucket._id }).patch(
			{
				registrationOpen: false,
				emailVerificationRequired: true,
				verificationMethod: 'code'
			},
			{ headers: { cookie } }
		);
		expect(patched.status).toBe(200);
		const after = patched.data as UserBucket;
		expect(after.registrationOpen).toBe(false);
		expect(after.emailVerificationRequired).toBe(true);
		expect(after.verificationMethod).toBe('code');

		const audit = await adminAuditStore.list({
			targetType: 'UserBucket',
			targetId: bucket._id
		});
		expect(audit.some((a) => a.action === 'bucket.settings.update')).toBe(true);
	});

	it('rejects an invalid verification method', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'BadMethod' },
			{ headers: { cookie } }
		);
		const bucket = created.data as UserBucket;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ verificationMethod: 'sms' as 'link' }, { headers: { cookie } });
		expect(res.status).toBe(422);
	});
});
