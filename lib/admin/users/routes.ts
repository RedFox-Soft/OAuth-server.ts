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
import {
	assertConsoleStaysReachable,
	loadReachabilityState,
	reachableSuperAdministrators,
	reachableThroughProvider
} from '../federation/reachability.js';
import { canSignIn } from '../../end_users/can_sign_in.js';
import { signOutAdministrator } from './sign_out.js';
import { clearAttempts } from '../../totp/verify.js';
import { CreateAdminBody, UpdateAdminBody } from './schema.js';
import { presentUser } from '../users-end/routes.js';
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
import { revokeAccountAccess } from '../../end_users/revoke_access.js';

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
		throw new AdminError(409, 'email already exists', { field: 'email' });
	}
	if (actingId !== targetId) return;
	const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
	if (bucket?.emailVerificationRequired) {
		throw new AdminError(
			409,
			'you cannot change your own address while administrators must verify theirs: ask another super administrator, or turn verification off first',
			{ field: 'email' }
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
	const state = await loadReachabilityState();
	assertConsoleStaysReachable(
		{
			...state,
			superAdministrators: state.superAdministrators.filter(
				(user) => user._id !== targetId
			)
		},
		'Removing this super administrator'
	);
}

/* A new address can fall outside every provider's admitted domains as surely as a removal can. */
async function assertAddressKeepsConsoleReachable(
	targetId: string,
	email: string
): Promise<void> {
	const state = await loadReachabilityState();
	assertConsoleStaysReachable(
		{
			...state,
			superAdministrators: state.superAdministrators.map((user) =>
				user._id === targetId ? { ...user, email } : user
			)
		},
		'Changing this address'
	);
}

/*
 * The colleague to recover, refused on oneself: your own sessions end with Log out, and your own
 * authenticator is reset by another super administrator — a route that let you do either here would sign
 * you out of the request that asked.
 */
async function recoveryTarget(
	actingId: string,
	targetId: string,
	refusal: string
) {
	if (targetId === actingId) throw new AdminError(409, refusal);
	const target = await store().find(targetId);
	if (!target) throw new AdminError(404, 'admin not found');
	return target;
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
		return (await store().list()).map((u) => ({
			...presentUser(u),
			superAdmin: supers.has(u._id)
		}));
	})
	/*
	 * What turning password sign-in off would do to the console (specs/080): how this session signed in,
	 * where the caller is linked, how many super administrators could still get in, and who could not.
	 * Read before the change so the console can say it, not after.
	 */
	.get('/admin/api/admins/sign-in-readiness', async ({ admin }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const state = await loadReachabilityState();
		const accounts = await store().list();
		const caller = accounts.find((u) => u._id === ctx.userId);
		return {
			passwordLogin: state.passwordLogin,
			signedInWith: ctx.signedInWith,
			callerLinkedAt: (caller?.federated ?? [])
				.map((link) => link.providerId)
				.filter((id) => state.providers.some((p) => p.id === id && p.enabled)),
			reachableSuperAdministrators: reachableSuperAdministrators(state).length,
			unlinkedAdministrators: accounts
				.filter(
					(user) =>
						canSignIn(user) && !reachableThroughProvider(user, state.providers)
				)
				.map((user) => ({ id: user._id, email: user.email }))
		};
	})
	.post(
		'/admin/api/admins',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			if (await store().findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists', { field: 'email' });
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
			return { ...presentUser(user), superAdmin: false };
		},
		{ body: CreateAdminBody }
	)
	.patch(
		'/admin/api/admins/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			if (body.active === false) {
				// The same two refusals as the deactivation route: the update is another door to the same act.
				if (params.id === ctx.userId) {
					throw new AdminError(409, 'cannot deactivate yourself');
				}
				await assertNotLastSuperAdmin(params.id);
			}
			if (body.email !== undefined) {
				await assertAddressChangeable(ctx.userId, params.id, body.email);
				await assertAddressKeepsConsoleReachable(params.id, body.email);
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
					throw new AdminError(409, 'email already exists', {
						field: 'email'
					});
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
			return {
				...presentUser(updated),
				superAdmin: await isSuperAdmin(updated._id)
			};
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
	/*
	 * Sign an administrator out everywhere: for a lost or stolen device. The account stays as it is.
	 */
	.post('/admin/api/admins/:id/sign-out', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const target = await recoveryTarget(
			ctx.userId,
			params.id,
			'you cannot sign yourself out from here — use Log out'
		);
		await recordAdminAudit(ctx, 'admin.signout', target._id);
		return { sessions: await signOutAdministrator(target._id) };
	})
	/*
	 * Reset an administrator's authenticator: for a lost device. They enrol afresh at their next sign-in,
	 * and are signed out now, because a session obtained with a factor the account no longer holds must not
	 * outlive it. Refused when there is nothing to reset, so an operator is told they had the wrong person.
	 */
	.delete('/admin/api/admins/:id/totp', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const target = await recoveryTarget(
			ctx.userId,
			params.id,
			'you cannot reset your own authenticator — ask another super administrator'
		);
		if (!target.totp) {
			throw new AdminError(409, 'no authenticator to reset');
		}
		await recordAdminAudit(ctx, 'admin.totp.clear', target._id);
		const updated = await store().update(target._id, { totp: undefined });
		if (!updated) throw new AdminError(404, 'admin not found');
		// So a re-enrolment does not begin inside a lockout the lost device earned.
		await clearAttempts(ADMIN_BUCKET_ID, target._id);
		return { sessions: await signOutAdministrator(target._id) };
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
		/*
		 * Everything they hold ends now, as it does for an end user made unable to sign in. The console and `/mcp`
		 * re-read `active` on every request and `findAccount` refuses a refresh, but an application of the
		 * administrators' project (specs/109) holds tokens that would otherwise live out their lifetime.
		 */
		await revokeAccountAccess(params.id);
		return { ok: true };
	});
