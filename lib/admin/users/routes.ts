import { Elysia } from 'elysia';
import { getBucketStore, getUserStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	AdminSettingsBody,
	CreateAdminBody,
	UpdateAdminBody
} from './schema.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import { ensurePersonalGroup } from '../groups/personal.js';

const store = () => getUserStore(ADMIN_BUCKET_ID);

/*
 * The reserved bucket record. Seeded by ensureAdminSeed and never deletable, so a miss here is a
 * broken deployment rather than a caller's mistake — said plainly instead of collapsing to a default
 * that would report "no second factor required" for a bucket nobody could find.
 */
async function adminBucket() {
	const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
	if (!bucket) throw new AdminError(500, 'the admin bucket is missing');
	return bucket;
}

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
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/admins', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return (await store().list()).map(({ password: _password, ...u }) => u);
	})
	/*
	 * The reserved admin bucket's own policy, which the generic bucket routes refuse to touch — their
	 * 403 names this namespace as the place it lives, and until now that promise had nothing behind it.
	 *
	 * Both halves are declared before `/admin/api/admins/:id`, because `:id` matches a single segment
	 * and `settings` is one: a request here must not be read as "the administrator whose id is
	 * `settings`". The ordering is the guard, and test/admin/admin_settings.spec.ts pins the outcome
	 * rather than trusting the router's precedence to stay as it is.
	 */
	.get('/admin/api/admins/settings', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return { totpRequired: (await adminBucket()).totpRequired === true };
	})
	.patch(
		'/admin/api/admins/settings',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			// Audit-first, like every other state-changing admin action. Field names, never values.
			await recordAdminAudit(ctx, 'admin.settings.update', ADMIN_BUCKET_ID, {
				attributes: Object.keys(body)
			});
			const updated = await getBucketStore().update(ADMIN_BUCKET_ID, {
				totpRequired: body.totpRequired
			});
			if (!updated) throw new AdminError(404, 'admin bucket not found');
			/*
			 * Nobody is locked out by turning this on: an administrator with no authenticator is taken
			 * through enrolment at their next sign-in, which is the same path that brings any existing
			 * account under the requirement.
			 */
			return { totpRequired: updated.totpRequired === true };
		},
		{ body: AdminSettingsBody }
	)
	.post(
		'/admin/api/admins',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			if (await store().findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists');
			}
			const hash = await Bun.password.hash(body.password);
			// Allocated here so the entry names the account that is about to exist. After the uniqueness
			// check, so a refused duplicate leaves no entry describing an account nobody created.
			const userId = nanoid();
			await recordAdminAudit(ctx, 'admin.create', userId);
			const user = await store().create(
				body.email,
				hash,
				body.roles,
				false,
				userId
			);
			// Every administrator owns exactly one personal group, created with the account: it is the
			// scope their console opens in, and without it they would sign in pointed at nothing.
			await ensurePersonalGroup(user._id, user.email);
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
			// After the last-super-admin guard: an entry for a request that guard refused would record a
			// role change that never happened.
			await recordAdminAudit(ctx, 'admin.update', params.id, {
				attributes: Object.keys(body)
			});
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
		// `admin.deactivate`, not a delete: the row survives with active:false.
		await recordAdminAudit(ctx, 'admin.deactivate', params.id);
		const updated = await store().update(params.id, { active: false });
		if (!updated) throw new AdminError(404, 'admin not found');
		return { ok: true };
	});
