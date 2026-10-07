import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { answered } from './answered.ts';
import { isSuperAdmin } from 'lib/admin/super_admins.ts';
import { present } from 'test/shape.js';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(adminUserRoutes);
const client = treaty(app);
const superAdminOf = (id: string) =>
	client.admin.api.admins({ id })['super-admin'];

async function cookieFor(kind: AdminKind) {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

/**
 * @proves Administrator accounts are created, listed, amended and deactivated only by an
 * instance owner, and their passwords never appear in a response.
 */
describe('admin-accounts API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('a super administrator creates an administrator who is not a super administrator', async () => {
		const { cookie } = await cookieFor('super');
		const res = await client.admin.api.admins.post(
			{
				email: 'pa@x.io',
				password: 'correct horse battery'
			},
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = await getUserStore(ADMIN_BUCKET_ID).findByEmail('pa@x.io');
		expect(await isSuperAdmin(present(created, 'created')._id)).toBe(false);
	});

	it('never returns the password field, on create or list', async () => {
		const { cookie } = await cookieFor('super');
		const created = await client.admin.api.admins.post(
			{
				email: 'nopw@x.io',
				password: 'correct horse battery'
			},
			{ headers: { cookie } }
		);
		expect(created.data).not.toHaveProperty('password');
		const list = await client.admin.api.admins.get({ headers: { cookie } });
		const admins = answered(list.data);
		expect(admins.every((u) => !('password' in u))).toBe(true);
	});

	it('a project administrator cannot list administrator accounts', async () => {
		const { cookie } = await cookieFor('plain');
		const res = await client.admin.api.admins.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});

	it('a project administrator is forbidden from creating admins', async () => {
		const { cookie } = await cookieFor('plain');
		const res = await client.admin.api.admins.post(
			{
				email: 'blocked@x.io',
				password: 'correct horse battery'
			},
			{ headers: { cookie } }
		);
		expect(res.status).toBe(403);
	});

	it('rejects anonymous access with 401', async () => {
		const res = await client.admin.api.admins.get();
		expect(res.status).toBe(401);
	});

	it('a super administrator deactivates another admin via DELETE', async () => {
		const { cookie } = await cookieFor('super');
		const target = await cookieFor('plain');
		const res = await client.admin.api
			.admins({ id: target.userId })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
		const found = await getUserStore(ADMIN_BUCKET_ID).find(target.userId);
		expect(found?.active).toBe(false);
	});

	it('rejects self-deactivation with 409', async () => {
		const { cookie, userId } = await cookieFor('super');
		const res = await client.admin.api
			.admins({ id: userId })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(409);
	});

	it('a super administrator makes another administrator a super administrator', async () => {
		const { cookie } = await cookieFor('super');
		const target = await cookieFor('plain');
		const res = await superAdminOf(target.userId).post(undefined, {
			headers: { cookie }
		});
		expect(res.status).toBe(200);
		expect(res.data).not.toHaveProperty('password');
		expect(await isSuperAdmin(target.userId)).toBe(true);
	});
});
