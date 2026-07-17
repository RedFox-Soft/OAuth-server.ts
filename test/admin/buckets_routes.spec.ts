import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { UserBucket } from 'lib/adapters/types.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function superCookie() {
	return (await sessionCookieFor(['super_admin'])).cookie;
}

describe('buckets API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a standalone bucket', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: 'Dev users', roles: ['viewer'] },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = res.data as UserBucket | undefined;
		expect(created?.authMethods).toEqual(['password']);
	});

	it('refuses to delete a bucket still referenced by a project', async () => {
		const cookie = await superCookie();
		const res1 = await client.admin.api.buckets.post(
			{ name: 'Shared' },
			{ headers: { cookie } }
		);
		const bucket = res1.data as UserBucket;
		const project = await getProjectStore().create({ name: 'P', slug: 'p' });
		await getProjectStore().update(project._id, { bucketId: bucket._id });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(409);
	});

	it('super_admin GET /admin/api/buckets returns all buckets', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const otherPa = await sessionCookieFor(['project_admin']);
		const a = await client.admin.api.buckets.post(
			{ name: 'Bucket A' },
			{ headers: { cookie } }
		);
		const b = await client.admin.api.buckets.post(
			{ name: 'Bucket B', managedBy: [otherPa.userId] },
			{ headers: { cookie } }
		);
		const bucketA = a.data as UserBucket;
		const bucketB = b.data as UserBucket;
		const list = await client.admin.api.buckets.get({ headers: { cookie } });
		const buckets = list.data as UserBucket[];
		const ids = buckets.map((bucket) => bucket._id);
		expect(ids).toContain(bucketA._id);
		expect(ids).toContain(bucketB._id);
	});

	it('project_admin GET /admin/api/buckets returns only buckets they manage', async () => {
		const superSession = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const otherPa = await sessionCookieFor(['project_admin']);
		const mine = await client.admin.api.buckets.post(
			{ name: 'Mine', managedBy: [pa.userId] },
			{ headers: { cookie: superSession.cookie } }
		);
		await client.admin.api.buckets.post(
			{ name: 'Other', managedBy: [otherPa.userId] },
			{ headers: { cookie: superSession.cookie } }
		);
		const bucketMine = mine.data as UserBucket;
		const list = await client.admin.api.buckets.get({
			headers: { cookie: pa.cookie }
		});
		const buckets = list.data as UserBucket[];
		expect(buckets.map((bucket) => bucket._id)).toEqual([bucketMine._id]);
	});

	it('project_admin cannot create a bucket', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const res = await client.admin.api.buckets.post(
			{ name: 'Denied' },
			{ headers: { cookie: pa.cookie } }
		);
		expect(res.status).toBe(403);
	});

	it('denies delete of an unreferenced bucket to a project_admin who does not manage it', async () => {
		const superSession = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const created = await client.admin.api.buckets.post(
			{ name: 'Not managed by pa' },
			{ headers: { cookie: superSession.cookie } }
		);
		const bucket = created.data as UserBucket;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('super_admin deletes an unreferenced bucket successfully', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'To delete' },
			{ headers: { cookie } }
		);
		const bucket = created.data as UserBucket;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
	});
});
