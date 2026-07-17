import { Elysia } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { CreateAdminBody, UpdateAdminBody } from './schema.js';

const store = () => getUserStore(ADMIN_BUCKET_ID);

// Count how many active super_admins would remain if the target admin's roles /
// active flag were changed as described. Used to prevent removing the last active
// super_admin, which would lock everyone out (resolveAdmin requires an active
// user, yet first-run setup stays closed while any super_admin row exists).
async function activeSuperAdminCountAfter(
	targetId: string,
	change: { roles?: string[]; active?: boolean }
): Promise<number> {
	const users = await store().list();
	let count = 0;
	for (const u of users) {
		const roles =
			u._id === targetId && change.roles !== undefined ? change.roles : u.roles;
		const active =
			u._id === targetId && change.active !== undefined
				? change.active
				: u.active;
		if (active && roles.includes('super_admin')) count += 1;
	}
	return count;
}

export const adminUserRoutes = new Elysia({ name: 'admin-users' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.get('/admin/api/admins', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return (await store().list()).map(({ password: _password, ...u }) => u);
	})
	.post(
		'/admin/api/admins',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			if (await store().findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists');
			}
			const hash = await Bun.password.hash(body.password);
			const user = await store().create(body.email, hash, body.roles);
			set.status = 201;
			const { password: _password, ...safe } = user;
			return safe;
		},
		{ body: CreateAdminBody }
	)
	.patch(
		'/admin/api/admins/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			if (
				(body.roles !== undefined || body.active !== undefined) &&
				(await activeSuperAdminCountAfter(params.id, body)) === 0
			) {
				throw new AdminError(409, 'cannot remove the last active super_admin');
			}
			const updated = await store().update(params.id, body);
			if (!updated) throw new AdminError(404, 'admin not found');
			const { password: _password, ...safe } = updated;
			return safe;
		},
		{ body: UpdateAdminBody }
	)
	.delete('/admin/api/admins/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		if (params.id === ctx.userId) {
			throw new AdminError(409, 'cannot deactivate yourself');
		}
		if (
			(await activeSuperAdminCountAfter(params.id, { active: false })) === 0
		) {
			throw new AdminError(409, 'cannot remove the last active super_admin');
		}
		const updated = await store().update(params.id, { active: false });
		if (!updated) throw new AdminError(404, 'admin not found');
		return { ok: true };
	});
