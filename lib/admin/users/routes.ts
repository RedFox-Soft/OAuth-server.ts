import { Elysia } from 'elysia';
import {
	getBucketStore,
	getGroupStore,
	getPasskeyStore,
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
	reachablePasskeySuperAdministrators,
	reachableSuperAdministrators,
	reachableThroughProvider
} from '../federation/reachability.js';
import { canSignIn } from '../../end_users/can_sign_in.js';
import { meets } from '../../helpers/acr_satisfaction.ts';
import { passkeyWorks } from '../../passkeys/account.js';
import {
	checkAdminPasskeyLinkEligibility,
	issueAdminPasskeyLink
} from '../../passkeys/admin_link.js';
import { notifyPasskey } from '../../passkeys/notify.js';
import { mailDeliveryConfigured } from '../../mail/mailer.js';
import { rpIdFor } from '../../passkeys/relying_party.js';
import { passkeysOfPerson } from '../../passkeys/ways_in.js';
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
import { UserActivityBody } from '../users-end/schema.js';
import {
	Names,
	activityFeed,
	activityPage,
	signInSummary
} from '../../person_activity/read.js';
import { recordReadOnce } from '../../person_activity/audit.js';

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
	/*
	 * `signIns` (specs/137): the last sign-in and what refused the administrator after it, with no address, country or
	 * device, so the list stays an unaudited read; where from is behind Sign-ins, which is audited.
	 */
	.get('/admin/api/admins', async ({ admin }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const supers = new Set(await superAdminIds());
		const accounts = await store().list();
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		const names = bucket ? new Names(bucket) : null;
		const now = new Date();
		const passkeyCounts = new Map(
			bucket
				? (
						await getPasskeyStore().holdingIn(ADMIN_BUCKET_ID, rpIdFor(bucket))
					).map((holder) => [holder.accountId, holder.passkeys])
				: []
		);
		return Promise.all(
			accounts.map(async (u) => ({
				...presentUser(u),
				superAdmin: supers.has(u._id),
				passkeys: passkeyCounts.get(u._id) ?? 0,
				signIns:
					bucket && names
						? await signInSummary(bucket, u._id, now, names)
						: { lastSignIn: null, notLetInSince: null }
			}))
		);
	})
	/*
	 * What turning password sign-in off or requiring a passkey for console sign-in would do (specs/080, specs/144):
	 * how this session signed in, where the caller is linked, whether they hold a working passkey, how many super
	 * administrators could still get in, and who could not. Read before the change so the console can say it, not after.
	 */
	.get('/admin/api/admins/sign-in-readiness', async ({ admin }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const state = await loadReachabilityState();
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		const accounts = await store().list();
		const caller = accounts.find((u) => u._id === ctx.userId);
		const holderSet = new Set(
			bucket
				? (
						await getPasskeyStore().holdingIn(ADMIN_BUCKET_ID, rpIdFor(bucket))
					).map((holder) => holder.accountId)
				: []
		);
		return {
			passwordLogin: state.passwordLogin,
			passkeyLogin: state.passkeyLogin,
			consolePasskeyRequired: state.consolePasskeyRequired,
			mailDeliveryConfigured: await mailDeliveryConfigured(),
			signedInWith: ctx.signedInWith,
			signedInWithPasskey: meets(ctx.signInAcr, 'phishing_resistant'),
			callerHasPasskey: holderSet.has(ctx.userId),
			callerLinkedAt: (caller?.federated ?? [])
				.map((link) => link.providerId)
				.filter((id) => state.providers.some((p) => p.id === id && p.enabled)),
			reachableSuperAdministrators: reachableSuperAdministrators(state).length,
			reachablePasskeySuperAdministrators:
				reachablePasskeySuperAdministrators(state).length,
			unlinkedAdministrators: accounts
				.filter(
					(user) =>
						canSignIn(user) && !reachableThroughProvider(user, state.providers)
				)
				.map((user) => ({ id: user._id, email: user.email })),
			administratorsWithoutPasskey: accounts
				.filter((user) => canSignIn(user) && !holderSet.has(user._id))
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
					// A new address is unproven, whoever typed it, and starts the 7-day passkey-link cooldown (specs/145).
					body.email !== undefined
						? { ...body, verified: false, emailChangedAt: new Date() }
						: body
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
	/*
	 * An administrator's passkeys (specs/144 contracts/admin-api.md §2): super administrators only, safe projection
	 * (no credential id, public key, counter, transports, AAGUID or disown state), not audited because it is a read.
	 */
	.get('/admin/api/admins/:id/passkeys', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const target = await store().find(params.id);
		if (!target) throw new AdminError(404, 'admin not found');
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		if (!bucket)
			throw new AdminError(500, "the administrators' project is missing");
		const held = await getPasskeyStore().listOf(ADMIN_BUCKET_ID, target._id);
		return passkeysOfPerson(bucket, target, held);
	})
	/*
	 * Revoke one passkey of another administrator (specs/144): refused on oneself, checks console reachability
	 * before auditing, writes audit-first with count only, removes, signs out everywhere, and emails the administrator.
	 */
	.delete(
		'/admin/api/admins/:id/passkeys/:passkeyId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			const target = await recoveryTarget(
				ctx.userId,
				params.id,
				'you cannot revoke your own passkeys from here — remove them from your account menu, or ask another super administrator'
			);
			const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
			if (!bucket)
				throw new AdminError(500, "the administrators' project is missing");
			const passkeyStore = getPasskeyStore();
			const passkey = await passkeyStore.find(
				ADMIN_BUCKET_ID,
				params.passkeyId
			);
			if (!passkey || passkey.accountId !== target._id) {
				throw new AdminError(404, 'passkey not found');
			}
			if (passkeyWorks(passkey, bucket)) {
				const state = await loadReachabilityState();
				if (state.superAdministrators.some((s) => s._id === target._id)) {
					const nextCounts = new Map(state.superAdminPasskeyCounts);
					nextCounts.set(
						target._id,
						Math.max(0, (nextCounts.get(target._id) ?? 0) - 1)
					);
					assertConsoleStaysReachable(
						{ ...state, superAdminPasskeyCounts: nextCounts },
						"Revoking this super administrator's passkey"
					);
				}
			}
			await recordAdminAudit(ctx, 'admin.passkey.revoke', target._id, {
				cascade: { passkeys: 1 }
			});
			const removed = await passkeyStore.remove(
				ADMIN_BUCKET_ID,
				target._id,
				passkey._id
			);
			if (!removed) throw new AdminError(404, 'passkey not found');
			const sessions = await signOutAdministrator(target._id);
			const mailed = await notifyPasskey(bucket, target, {
				kind: 'revoked',
				madeOn: passkey.createdOn,
				createdAt: new Date(passkey.createdAt).getTime()
			});
			return { revoked: 1, sessions, mailed };
		}
	)
	/* Revoke every passkey of another administrator (specs/144). */
	.delete('/admin/api/admins/:id/passkeys', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const target = await recoveryTarget(
			ctx.userId,
			params.id,
			'you cannot revoke your own passkeys from here — remove them from your account menu, or ask another super administrator'
		);
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		if (!bucket)
			throw new AdminError(500, "the administrators' project is missing");
		const passkeyStore = getPasskeyStore();
		const held = await passkeyStore.listOf(ADMIN_BUCKET_ID, target._id);
		if (held.length === 0) {
			throw new AdminError(409, 'no passkeys to revoke');
		}
		if (held.some((p) => passkeyWorks(p, bucket))) {
			const state = await loadReachabilityState();
			if (state.superAdministrators.some((s) => s._id === target._id)) {
				const nextCounts = new Map(state.superAdminPasskeyCounts);
				nextCounts.set(target._id, 0);
				assertConsoleStaysReachable(
					{ ...state, superAdminPasskeyCounts: nextCounts },
					"Revoking this super administrator's passkeys"
				);
			}
		}
		await recordAdminAudit(ctx, 'admin.passkey.revoke.all', target._id, {
			cascade: { passkeys: held.length }
		});
		const revoked = await passkeyStore.removeAllOf(ADMIN_BUCKET_ID, target._id);
		const sessions = await signOutAdministrator(target._id);
		const mailed = await notifyPasskey(bucket, target, {
			kind: 'revoked_all',
			count: revoked
		});
		return { revoked, sessions, mailed };
	})
	/*
	 * Send a 24-hour single-use passkey setup link to another administrator (specs/145 US3, S14): super-admin only,
	 * never self, mailed ONLY (204 No Content — never returned in API/MCP or written to the audit trail).
	 */
	.post('/admin/api/admins/:id/passkey-link', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const target = await recoveryTarget(
			ctx.userId,
			params.id,
			'you cannot send a passkey setup link to yourself — add a passkey from your account menu, or ask another super administrator'
		);
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		if (!bucket)
			throw new AdminError(500, "the administrators' project is missing");
		const eligible = await checkAdminPasskeyLinkEligibility(bucket, target);
		if (!eligible.ok) {
			throw new AdminError(eligible.status, eligible.message, {
				...(eligible.retryAfter !== undefined
					? { retryAfter: eligible.retryAfter }
					: {}),
				...(eligible.code === 'email_changed_recently' ||
				eligible.code === 'passkeys_not_accepted'
					? { code: eligible.code }
					: {})
			});
		}
		await recordAdminAudit(ctx, 'admin.passkey.link.send', target._id);
		const issued = await issueAdminPasskeyLink(bucket, target, ctx.userId);
		if (!issued.ok) {
			throw new AdminError(502, 'Could not deliver the passkey setup email.');
		}
		return new Response(null, { status: 204 });
	})
	/*
	 * Every administrator's sign-ins on one page (specs/137), for the super administrator who does not yet know whose
	 * password was taken. Audited like one administrator's, once per reader and day, against the administrators'
	 * project.
	 */
	.post(
		'/admin/api/admins/activity',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
			if (!bucket)
				throw new AdminError(404, "the administrators' project is missing");
			await recordReadOnce(
				ctx,
				bucket,
				'admins.activity.read',
				ADMIN_BUCKET_ID
			);
			return activityFeed(bucket, await store().list(), body);
		},
		{ body: UserActivityBody }
	)
	/*
	 * Where and how an administrator signed in (specs/137): the person's timeline reader over the administrators'
	 * project, which `loadBucketForUsers` keeps closed to every project route. A POST because reading it is audited,
	 * once per reader, administrator and day, as a person's timeline is; the audit is after the check, so a refused
	 * caller leaves nothing.
	 */
	.post(
		'/admin/api/admins/:id/activity',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			const target = await store().find(params.id);
			if (!target) throw new AdminError(404, 'admin not found');
			const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
			if (!bucket) throw new AdminError(404, 'admin not found');
			await recordReadOnce(ctx, bucket, 'admin.activity.read', target._id);
			return activityPage(bucket, target._id, body);
		},
		{ body: UserActivityBody }
	)
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
