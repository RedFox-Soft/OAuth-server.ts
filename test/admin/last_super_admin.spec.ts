import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(adminUserRoutes);
const client = treaty(app);

async function makeAdmin(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${Math.random()}@x.io`,
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

// Reset the shared admin stores each test so the active-super_admin count is
// deterministic (other specs seed many super_admins into the same process).
describe('last active super_admin guard', () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	it('blocks demoting the only active super_admin (PATCH roles) with 409', async () => {
		const su = await makeAdmin(['super_admin']);
		const res = await client.admin.api
			.admins({ id: su.userId })
			.patch({ roles: ['project_admin'] }, { headers: { cookie: su.cookie } });
		expect(res.status).toBe(409);
	});

	it('blocks deactivating the only active super_admin (PATCH active:false) with 409', async () => {
		const su = await makeAdmin(['super_admin']);
		const res = await client.admin.api
			.admins({ id: su.userId })
			.patch({ active: false }, { headers: { cookie: su.cookie } });
		expect(res.status).toBe(409);
	});

	it('allows demoting a super_admin while another active super_admin remains', async () => {
		const a = await makeAdmin(['super_admin']);
		const b = await makeAdmin(['super_admin']);
		const res = await client.admin.api
			.admins({ id: b.userId })
			.patch({ roles: ['project_admin'] }, { headers: { cookie: a.cookie } });
		expect(res.status).toBe(200);
	});
});
