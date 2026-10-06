import { Elysia } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadBucketForUsers } from '../buckets/access.js';
import {
	CreateEndUserBody,
	LockEndUserBody,
	UpdateEndUserBody,
	ResetPasswordBody
} from './schema.js';
import { recordAdminAudit } from '../audit/record.js';
import { endSessionsForAccount } from '../../helpers/cascade.js';
import { clearAttempts } from '../../totp/verify.js';
import nanoid from '../../helpers/nanoid.js';
import {
	createEndUser,
	EndUserError,
	lockEndUser,
	removeEndUser,
	resetEndUserPassword,
	unlockEndUser,
	updateEndUser,
	type EndUserActor
} from '../../end_users/service.js';

/* Every change made here is an administrator's. */
const ADMIN: EndUserActor = { kind: 'admin' };

/* The service's refusals, in the admin plane's own error shape. */
async function asAdmin<T>(operation: Promise<T>): Promise<T> {
	try {
		return await operation;
	} catch (error) {
		if (error instanceof EndUserError) {
			throw new AdminError(error.status, error.message);
		}
		throw error;
	}
}

/*
 * The one shape an end-user record takes on its way out of this server.
 *
 * Two fields never leave, and for different reasons. `password` is a hash nobody needs. `totp` is the
 * shared secret behind an authenticator, and unlike a password it cannot be hashed — TOTP verification
 * is symmetric, so the server has to hold something recoverable. That makes "it never appears in a
 * read" the whole of its protection, and the protection has to live in one function rather than at
 * each of the four call sites: a presenter somebody forgets on one route is exactly how every
 * administrator came to be handed every bucket's federation secrets (lib/admin/buckets/routes.ts).
 *
 * What an operator legitimately needs — whether there is an authenticator, and since when — is derived
 * here instead, so answering that question never involves handling the secret.
 *
 * test/mcp/secrecy.spec.ts sweeps every published read for exactly this.
 */
export const presentUser = <
	T extends {
		password?: string;
		totp?: { enrolledAt: Date };
		userNameKey?: string;
		externalIdKey?: string;
	}
>(
	user: T
) => {
	/* The derived keys are index material, not facts about the person; they stay with the store. */
	const {
		password: _password,
		totp,
		userNameKey: _userNameKey,
		externalIdKey: _externalIdKey,
		...safe
	} = user;
	return {
		...safe,
		totpEnrolled: Boolean(totp),
		totpEnrolledAt: totp?.enrolledAt?.toISOString() ?? null
	};
};

export const endUserRoutes = new Elysia({ name: 'admin-users-end' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/buckets/:id/users', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		await loadBucketForUsers(ctx, params.id);
		const users = await getUserStore(params.id).list();
		return users.map(presentUser);
	})
	.post(
		'/admin/api/buckets/:id/users',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			// Allocated here so the entry names the account that is about to exist. The bucket travels as
			// the scope: these users live in per-bucket storage, so an id alone resolves to nobody.
			const userId = nanoid();
			const user = await asAdmin(
				createEndUser(
					bucket,
					ADMIN,
					{
						id: userId,
						email: body.email,
						password: body.password,
						verified: true,
						roles: body.roles,
						claims: body.claims
					},
					() =>
						recordAdminAudit(ctx, 'enduser.create', userId, {
							targetScope: params.id
						})
				)
			);
			set.status = 201;
			return presentUser(user);
		},
		{ body: CreateEndUserBody }
	)
	.patch(
		'/admin/api/buckets/:id/users/:uid',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const { user, revoked } = await asAdmin(
				updateEndUser(bucket, ADMIN, params.uid, body, () =>
					// Names only: the values are personal data, and the trail is kept longer than the account.
					recordAdminAudit(ctx, 'enduser.update', params.uid, {
						targetScope: params.id,
						attributes: Object.keys(body)
					})
				)
			);
			/*
			 * Reported the way the authenticator reset beside it reports a partial sweep: the user is already
			 * unable to sign in, so nothing is unsafe, but the operator is told what survived and that
			 * deactivating again sweeps again. Not in the audit entry — that is written before the change.
			 */
			if (revoked && revoked.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`the user was deactivated, but their access survives in: ${revoked.failedAreas.join(', ')}`,
					{ failedAreas: revoked.failedAreas }
				);
			}
			return presentUser(user);
		},
		{ body: UpdateEndUserBody }
	)
	.post(
		'/admin/api/buckets/:id/users/:uid/password',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			await asAdmin(
				resetEndUserPassword(bucket, ADMIN, params.uid, body.password, () =>
					// The reset is the recorded fact. No attribute names either: naming the field would say
					// nothing the action does not, and the value must never be near the trail.
					recordAdminAudit(ctx, 'enduser.password.reset', params.uid, {
						targetScope: params.id
					})
				)
			);
			return { ok: true };
		},
		{ body: ResetPasswordBody }
	)
	/*
	 * The emergency block: ends the user's access at once and holds until an administrator lifts it, whatever
	 * the user's provisioning connection sends. The reason lives on the record, not in the trail.
	 */
	.post(
		'/admin/api/buckets/:id/users/:uid/lock',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const { user, revoked } = await asAdmin(
				lockEndUser(
					bucket,
					params.uid,
					{ by: ctx.userId, reason: body.reason },
					() =>
						recordAdminAudit(ctx, 'enduser.lock', params.uid, {
							targetScope: params.id
						})
				)
			);
			if (revoked && revoked.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`the user was locked, but their access survives in: ${revoked.failedAreas.join(', ')}`,
					{ failedAreas: revoked.failedAreas }
				);
			}
			return presentUser(user);
		},
		{ body: LockEndUserBody }
	)
	.post(
		'/admin/api/buckets/:id/users/:uid/unlock',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const user = await asAdmin(
				unlockEndUser(bucket, params.uid, () =>
					recordAdminAudit(ctx, 'enduser.unlock', params.uid, {
						targetScope: params.id
					})
				)
			);
			return presentUser(user);
		}
	)
	/*
	 * Recovery for a lost authenticator: clear the enrolment, and the account enrols afresh at its next
	 * sign-in. Ordinary and audited rather than gated, because it is the *recovery* action — the harm it
	 * undoes is someone permanently locked out, and what it costs is one re-enrolment.
	 *
	 * Deliberately a reset and not a deletion. Sessions go, because a session obtained with a factor the
	 * account no longer holds must not outlive it; grants and tokens stay, because revoking a token is
	 * not withdrawing consent (lib/helpers/cascade.ts states this boundary).
	 *
	 * Idempotent: clearing an account that holds no authenticator succeeds, and still records. An
	 * operator should not have to know the current state to reach the one they want.
	 */
	.delete(
		'/admin/api/buckets/:id/users/:uid/totp',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForUsers(ctx, params.id);

			// Audit-first, as the password reset beside it is: a mutation is not reported successful
			// unless its entry was recorded. No attribute names and no values — the act is the whole fact.
			await recordAdminAudit(ctx, 'enduser.totp.clear', params.uid, {
				targetScope: params.id
			});

			const updated = await getUserStore(params.id).update(params.uid, {
				totp: undefined
			});
			if (!updated) throw new AdminError(404, 'user not found');

			// So a re-enrolment does not begin inside a lockout the lost device earned.
			await clearAttempts(params.id, params.uid);

			const cascade = await endSessionsForAccount(params.uid);
			if (cascade.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`the authenticator was cleared, but sessions survive in: ${cascade.failedAreas.join(', ')}`,
					{ failedAreas: cascade.failedAreas }
				);
			}
			return { ok: true };
		}
	)
	.delete('/admin/api/buckets/:id/users/:uid', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const bucket = await loadBucketForUsers(ctx, params.id);
		const cascade = await asAdmin(
			removeEndUser(bucket, ADMIN, params.uid, () =>
				recordAdminAudit(ctx, 'enduser.delete', params.uid, {
					targetScope: params.id
				})
			)
		);
		if (cascade.failedAreas.length > 0) {
			throw new AdminError(
				500,
				`user deleted, but their records survive in: ${cascade.failedAreas.join(', ')}`,
				{ failedAreas: cascade.failedAreas }
			);
		}
		return { ok: true, destroyed: cascade.destroyed };
	});
