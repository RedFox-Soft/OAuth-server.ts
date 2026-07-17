import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminSessionStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { User } from 'lib/adapters/types.ts';

const app = new Elysia().use(resolveAdmin).use(adminUserRoutes);
const client = treaty(app);

async function cookieFor(roles: string[]) {
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

describe('admin-accounts API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('super_admin creates a project_admin', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const res = await client.admin.api.admins.post(
			{
				email: 'pa@x.io',
				password: 'correct horse battery',
				roles: ['project_admin']
			},
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = await getUserStore(ADMIN_BUCKET_ID).findByEmail('pa@x.io');
		expect(created?.roles).toEqual(['project_admin']);
	});

	it('never returns the password field, on create or list', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const created = await client.admin.api.admins.post(
			{
				email: 'nopw@x.io',
				password: 'correct horse battery',
				roles: ['project_admin']
			},
			{ headers: { cookie } }
		);
		expect(created.data).not.toHaveProperty('password');
		const list = await client.admin.api.admins.get({ headers: { cookie } });
		const admins = list.data as Omit<User, 'password'>[] | undefined;
		expect(admins?.every((u) => !('password' in u))).toBe(true);
	});

	it('project_admin is forbidden', async () => {
		const { cookie } = await cookieFor(['project_admin']);
		const res = await client.admin.api.admins.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});

	it('project_admin is forbidden from creating admins', async () => {
		const { cookie } = await cookieFor(['project_admin']);
		const res = await client.admin.api.admins.post(
			{
				email: 'blocked@x.io',
				password: 'correct horse battery',
				roles: ['project_admin']
			},
			{ headers: { cookie } }
		);
		expect(res.status).toBe(403);
	});

	it('rejects anonymous access with 401', async () => {
		const res = await client.admin.api.admins.get();
		expect(res.status).toBe(401);
	});

	it('super_admin deactivates another admin via DELETE', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const target = await cookieFor(['project_admin']);
		const res = await client.admin.api
			.admins({ id: target.userId })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
		const found = await getUserStore(ADMIN_BUCKET_ID).find(target.userId);
		expect(found?.active).toBe(false);
	});

	it('rejects self-deactivation with 409', async () => {
		const { cookie, userId } = await cookieFor(['super_admin']);
		const res = await client.admin.api
			.admins({ id: userId })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(409);
	});

	it('super_admin patches roles/active on an admin', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const target = await cookieFor(['project_admin']);
		const res = await client.admin.api
			.admins({ id: target.userId })
			.patch({ roles: ['super_admin'] }, { headers: { cookie } });
		expect(res.status).toBe(200);
		expect(res.data).not.toHaveProperty('password');
		const found = await getUserStore(ADMIN_BUCKET_ID).find(target.userId);
		expect(found?.roles).toEqual(['super_admin']);
	});
});
