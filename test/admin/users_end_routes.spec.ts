import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getBucketStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { UserBucket } from 'lib/adapters/types.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes).use(endUserRoutes);
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

async function makeBucket(roles: string[] = [], managedBy: string[] = []) {
	return getBucketStore().create({
		name: `b-${Math.random()}`,
		roles,
		managedBy
	});
}

describe('end-user API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('rejects anonymous access', async () => {
		const bucket = await makeBucket();
		const res = await client.admin.api.buckets({ id: bucket._id }).users.get();
		expect(res.status).toBe(401);
	});

	it('creates, lists (no password), edits, and deletes a user', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket(['viewer']);
		const created = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'u@x.io', password: 'supersecret', roles: ['viewer'] },
				{ headers: { cookie } }
			);
		expect(created.status).toBe(201);
		const body = created.data as Record<string, unknown>;
		expect(body.password).toBeUndefined();
		expect(body.verified).toBe(true);
		const uid = body._id as string;

		const list = await client.admin.api
			.buckets({ id: bucket._id })
			.users.get({ headers: { cookie } });
		const users = list.data as Array<Record<string, unknown>>;
		expect(users.some((u) => u._id === uid)).toBe(true);
		expect(users.every((u) => u.password === undefined)).toBe(true);

		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.patch({ active: false }, { headers: { cookie } });
		expect((patched.data as Record<string, unknown>).active).toBe(false);

		const del = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.delete(undefined, { headers: { cookie } });
		expect(del.status).toBe(200);
		expect(await getUserStore(bucket._id).find(uid)).toBeNull();
	});

	it('rejects roles not in the bucket set with 422', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket(['viewer']);
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'bad@x.io', password: 'supersecret', roles: ['admin'] },
				{ headers: { cookie } }
			);
		expect(res.status).toBe(422);
	});

	it('rejects a duplicate email with 409', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const body = { email: 'dup@x.io', password: 'supersecret' };
		await client.admin.api.buckets({ id: bucket._id }).users.post(body, { headers: { cookie } });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(body, { headers: { cookie } });
		expect(res.status).toBe(409);
	});

	it('resets a password (stores a new hash)', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const created = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post({ email: 'pw@x.io', password: 'supersecret' }, { headers: { cookie } });
		const uid = (created.data as Record<string, unknown>)._id as string;
		const before = (await getUserStore(bucket._id).find(uid))?.password;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.password.post({ password: 'anothersecret' }, { headers: { cookie } });
		expect(res.status).toBe(200);
		const after = (await getUserStore(bucket._id).find(uid))?.password;
		expect(after).not.toBe(before);
	});

	it('lets a project_admin manage users of a bucket backing their project', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const bucket = await makeBucket(); // not owned by pa
		const proj = await getProjectStore().create({
			name: 'PM',
			slug: `pm-${Math.random()}`,
			managedBy: [pa.userId]
		});
		await getProjectStore().update(proj._id, { bucketId: bucket._id });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post({ email: 'via@x.io', password: 'supersecret' }, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(201);
	});

	it('denies a project_admin a bucket they neither own nor reach via a project', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const bucket = await makeBucket();
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.get({ headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('refuses to manage users of the reserved admin bucket', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.users.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});
});
