import { Elysia } from 'elysia';
import {
	getBucketStore,
	getGroupStore,
	getUserStore
} from '../../adapters/index.js';
import { DuplicateEndUserError } from '../../adapters/types.js';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { CreateAdminBody, UpdateAdminBody } from './schema.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import { ensurePersonalGroup } from '../groups/personal.js';
import {
	activeSuperAdminsWithout,
	grantSuperAdmin,
	isSuperAdmin,
	superAdminIds,
	withdrawSuperAdmin
} from '../super_admins.js';

const store = () => getUserStore(ADMIN_BUCKET_ID);

/*
 * Before the audit entry, so a refused change records nothing.
 *
 * Changing your own address while administrators must verify theirs is refused: it makes you unverified at
 * an address nobody has proven, and a typo there locks out the person making the change — and, when they
 * are the last super administrator, the instance. Changing somebody else's cannot lock you out.
 */
async function assertAddressChangeable(
	actingId: string,
	targetId: string,
	email: string
): Promise<void> {
	const holder = await store().findByEmail(email);
	if (holder && holder._id !== targetId) {
		throw new AdminError(409, 'email already exists');
	}
	if (actingId !== targetId) return;
	const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
	if (bucket?.emailVerificationRequired) {
		throw new AdminError(
			409,
			'you cannot change your own address while administrators must verify theirs: ask another super administrator, or turn verification off first'
		);
	}
}

/*
 * Refuses a change that would leave no active super administrator: nobody could then grant the privilege
 * again, and first-run setup stays closed while the group has any member, so the instance would be locked.
 */
async function assertNotLastSuperAdmin(targetId: string): Promise<void> {
	if (
		(await isSuperAdmin(targetId)) &&
		(await activeSuperAdminsWithout(targetId)) === 0
	) {
		throw new AdminError(
			409,
			'cannot remove the last active super administrator'
		);
	}
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
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const supers = new Set(await superAdminIds());
		return (await store().list()).map(({ password: _password, ...u }) => ({
			...u,
			superAdmin: supers.has(u._id)
		}));
	})
	.post(
		'/admin/api/admins',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			if (await store().findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists');
			}
			const hash = await Bun.password.hash(body.password);
			// Allocated here so the entry names the account that is about to exist. After the uniqueness
			// check, so a refused duplicate leaves no entry describing an account nobody created.
			const userId = nanoid();
			await recordAdminAudit(ctx, 'admin.create', userId);
			const user = await store().create(body.email, hash, false, userId);
			// Every administrator owns exactly one personal group, created with the account: it is the
			// scope their console opens in, and without it they would sign in pointed at nothing.
			await ensurePersonalGroup(user._id, user.email);
			set.status = 201;
			const { password: _password, ...safe } = user;
			return { ...safe, superAdmin: false };
		},
		{ body: CreateAdminBody }
	)
	.patch(
		'/admin/api/admins/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			if (body.active === false) await assertNotLastSuperAdmin(params.id);
			if (body.email !== undefined) {
				await assertAddressChangeable(ctx.userId, params.id, body.email);
			}
			// After every guard: an entry for a request a guard refused would record a change that never
			// happened.
			await recordAdminAudit(ctx, 'admin.update', params.id, {
				attributes: Object.keys(body)
			});
			let updated;
			try {
				updated = await store().update(
					params.id,
					// A new address is unproven, whoever typed it.
					body.email !== undefined ? { ...body, verified: false } : body
				);
			} catch (err) {
				if (err instanceof DuplicateEndUserError) {
					throw new AdminError(409, 'email already exists');
				}
				throw err;
			}
			if (!updated) throw new AdminError(404, 'admin not found');
			if (body.email !== undefined) {
				/*
				 * The personal group's stored name *is* its owner's address — it is how everyone else tells
				 * whose it is — so it follows the account rather than naming somebody who no longer exists.
				 */
				const personal = await getGroupStore().findPersonalFor(params.id);
				if (personal) {
					await getGroupStore().update(personal._id, { name: updated.email });
				}
			}
			const { password: _password, ...safe } = updated;
			return { ...safe, superAdmin: await isSuperAdmin(updated._id) };
		},
		{ body: UpdateAdminBody }
	)
	/*
	 * The instance privilege, granted and withdrawn as membership of Super administrators — operations of
	 * their own, `high` on the agent surface, so that making somebody all-powerful is never a side effect of
	 * an account edit. Asserting what is already true changes nothing and records nothing.
	 */
	.post('/admin/api/admins/:id/super-admin', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const target = await store().find(params.id);
		if (!target) throw new AdminError(404, 'admin not found');
		if (!target.active) {
			throw new AdminError(
				409,
				'an inactive administrator cannot be granted it'
			);
		}
		if (!(await isSuperAdmin(target._id))) {
			await recordAdminAudit(ctx, 'admin.superadmin.grant', target._id);
			await grantSuperAdmin(target._id);
		}
		return { _id: target._id, email: target.email, superAdmin: true };
	})
	.delete('/admin/api/admins/:id/super-admin', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const target = await store().find(params.id);
		if (!target) throw new AdminError(404, 'admin not found');
		if (await isSuperAdmin(target._id)) {
			await assertNotLastSuperAdmin(target._id);
			await recordAdminAudit(ctx, 'admin.superadmin.withdraw', target._id);
			await withdrawSuperAdmin(target._id);
		}
		return { _id: target._id, email: target.email, superAdmin: false };
	})
	.delete('/admin/api/admins/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		if (params.id === ctx.userId) {
			throw new AdminError(409, 'cannot deactivate yourself');
		}
		await assertNotLastSuperAdmin(params.id);
		// `admin.deactivate`, not a delete: the row survives with active:false.
		await recordAdminAudit(ctx, 'admin.deactivate', params.id);
		const updated = await store().update(params.id, { active: false });
		if (!updated) throw new AdminError(404, 'admin not found');
		return { ok: true };
	});
