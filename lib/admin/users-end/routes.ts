import { Elysia } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
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
	UpdateEndUserBody,
	ResetPasswordBody
} from './schema.js';
import { recordAdminAudit } from '../audit/record.js';
import {
	cascadeForAccount,
	endSessionsForAccount
} from '../../helpers/cascade.js';
import { clearAttempts } from '../../totp/verify.js';
import nanoid from '../../helpers/nanoid.js';

function assertRolesSubset(
	roles: string[] | undefined,
	bucket: UserBucket
): void {
	if (!roles) return;
	const bad = roles.filter((r) => !bucket.roles.includes(r));
	if (bad.length) {
		throw new AdminError(
			422,
			`roles not declared on bucket: ${bad.join(', ')}`
		);
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
const presentUser = <
	T extends { password?: string; totp?: { enrolledAt: Date } }
>(
	user: T
) => {
	const { password: _password, totp, ...safe } = user;
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
			assertRolesSubset(body.roles, bucket);
			const store = getUserStore(params.id);
			if (await store.findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists');
			}
			const hash = await Bun.password.hash(body.password);
			// Allocated here so the entry names the account that is about to exist. The bucket travels as
			// the scope: these users live in per-bucket storage, so an id alone resolves to nobody.
			const userId = nanoid();
			await recordAdminAudit(ctx, 'enduser.create', userId, {
				targetScope: params.id
			});
			const user = await store.create(
				body.email,
				hash,
				body.roles ?? [],
				true,
				userId
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
			assertRolesSubset(body.roles, bucket);
			await recordAdminAudit(ctx, 'enduser.update', params.uid, {
				targetScope: params.id,
				attributes: Object.keys(body)
			});
			const updated = await getUserStore(params.id).update(params.uid, body);
			if (!updated) throw new AdminError(404, 'user not found');
			return presentUser(updated);
		},
		{ body: UpdateEndUserBody }
	)
	.post(
		'/admin/api/buckets/:id/users/:uid/password',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForUsers(ctx, params.id);
			const hash = await Bun.password.hash(body.password);
			// The reset is the recorded fact. No attribute names either: naming the field would say
			// nothing the action does not, and the value must never be near the trail.
			await recordAdminAudit(ctx, 'enduser.password.reset', params.uid, {
				targetScope: params.id
			});
			const updated = await getUserStore(params.id).update(params.uid, {
				password: hash
			});
			if (!updated) throw new AdminError(404, 'user not found');
			return { ok: true };
		},
		{ body: ResetPasswordBody }
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
		await loadBucketForUsers(ctx, params.id);
		const store = getUserStore(params.id);
		const user = await store.find(params.uid);
		if (!user) {
			throw new AdminError(404, 'user not found');
		}
		/*
		 * The email is read here, before the row goes, because the email-scoped areas (VerificationResend,
		 * PasswordResetThrottle) are addressed by `${bucketId}:${email}` and nothing else records it.
		 * Destroy first and those records are unreachable — skipped in silence, with no error anywhere to
		 * notice.
		 */
		const emailScopedId = user.email ? `${params.id}:${user.email}` : null;
		await recordAdminAudit(ctx, 'enduser.delete', params.uid, {
			targetScope: params.id
		});
		await store.destroy(params.uid);
		/* Audit, then destroy the principal, then cascade; a failed sweep is reported, never rolled back. */
		const cascade = await cascadeForAccount(params.uid, emailScopedId);
		if (cascade.failedAreas.length > 0) {
			throw new AdminError(
				500,
				`user deleted, but their records survive in: ${cascade.failedAreas.join(', ')}`,
				{ failedAreas: cascade.failedAreas }
			);
		}
		return { ok: true, destroyed: cascade.destroyed };
	});
