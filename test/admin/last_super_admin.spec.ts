import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(adminUserRoutes);
const client = treaty(app);
const superAdminOf = (id: string) =>
	client.admin.api.admins({ id })['super-admin'];

async function makeAdmin(kind: AdminKind) {
	const user = await createAdministrator(kind, `${Math.random()}@x.io`);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

// Reset the shared admin stores each test so the active super administrator count is
// deterministic (other specs seed many super administrators into the same process).
/**
 * @proves The instance can never be left with no active super administrator, by withdrawal or by
 * deactivation.
 */
describe('last active super administrator guard', () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	it('refuses to withdraw the only active super administrator with 409', async () => {
		const su = await makeAdmin('super');
		const res = await superAdminOf(su.userId).delete(undefined, {
			headers: { cookie: su.cookie }
		});
		expect(res.status).toBe(409);
	});

	it('refuses to deactivate the only active super administrator with 409', async () => {
		const su = await makeAdmin('super');
		const res = await client.admin.api
			.admins({ id: su.userId })
			.patch({ active: false }, { headers: { cookie: su.cookie } });
		expect(res.status).toBe(409);
	});

	it('withdraws a super administrator while another active one remains', async () => {
		const a = await makeAdmin('super');
		const b = await makeAdmin('super');
		const res = await superAdminOf(b.userId).delete(undefined, {
			headers: { cookie: a.cookie }
		});
		expect(res.status).toBe(200);
	});
});
