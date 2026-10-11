import { Elysia } from 'elysia';
import { getBucketGroupStore, getUserStore } from '../../adapters/index.js';
import {
	MAX_END_USER_PAGE,
	type EndUserFilter,
	type User
} from '../../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForUsers } from '../buckets/access.js';
import {
	ALLOWED_USER_LIST_PARAMS,
	ChangeEndUserEmailBody,
	CreateEndUserBody,
	LockEndUserBody,
	UpdateEndUserBody,
	ResetPasswordBody,
	UserListQuery
} from './schema.js';
import { mailDeliveryConfigured } from '../../mail/mailer.js';
import { sendOnDemand, sendRateRefused } from '../../verification/challenge.js';
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
	revokeEndUserAccess,
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
			throw new AdminError(
				error.status,
				error.message,
				error.field === undefined ? undefined : { field: error.field }
			);
		}
		throw error;
	}
}

/*
 * The one shape an account record takes on its way out of this server — an end user's, and an
 * administrator's too, since both are rows of a bucket's user store and an administrator can enrol an
 * authenticator like anyone else. The administrator routes once stripped only the password by hand and
 * so handed every administrator's authenticator secret to every super administrator and to the agent.
 *
 * Two fields never leave, and for different reasons. `password` is a hash nobody needs. `totp` is the
 * shared secret behind an authenticator, and unlike a password it cannot be hashed — TOTP verification
 * is symmetric, so the server has to hold something recoverable. That makes "it never appears in a
 * read" the whole of its protection, and the protection has to live in one function rather than at
 * each call site: a presenter somebody forgets on one route is exactly how every
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
		totpEnrolledAt: totp?.enrolledAt.toISOString() ?? null
	};
};

/* Each user with the groups they are in — the console's view of what a role column used to show. */
async function withGroups(bucketId: string, users: User[]) {
	const store = getBucketGroupStore();
	const groupIds = new Map<string, string[]>();
	for (let i = 0; i < users.length; i += MAX_END_USER_PAGE) {
		const page = await store.groupIdsOf(
			bucketId,
			users.slice(i, i + MAX_END_USER_PAGE).map((u) => u._id)
		);
		for (const [userId, ids] of page) groupIds.set(userId, ids);
	}
	const wanted = [...new Set([...groupIds.values()].flat())];
	const groups = new Map<
		string,
		{ id: string; displayName: string; provisionedBy?: string }
	>();
	for (let i = 0; i < wanted.length; i += MAX_END_USER_PAGE) {
		for (const g of await store.findMany(
			wanted.slice(i, i + MAX_END_USER_PAGE)
		)) {
			groups.set(g._id, {
				id: g._id,
				displayName: g.displayName,
				...(g.provisionedBy === undefined
					? {}
					: { provisionedBy: g.provisionedBy })
			});
		}
	}
	return users.map((user) => ({
		...presentUser(user),
		groups: (groupIds.get(user._id) ?? [])
			.map((id) => groups.get(id))
			.filter((g) => g !== undefined)
	}));
}

/*
 * Checked against the raw URL, because Elysia only lifts declared keys out of the query string: a mistyped
 * filter would be dropped and answered with everyone — a wrong list wearing a 200.
 */
function assertNoUnknownParams(url: string): void {
	const unknown = [...new URL(url).searchParams.keys()].filter(
		(name) => !ALLOWED_USER_LIST_PARAMS.has(name)
	);
	if (unknown.length > 0) {
		throw new AdminError(
			422,
			`unknown query parameter: ${[...new Set(unknown)].sort().join(', ')}`,
			unknown.length === 1 ? { field: unknown[0] } : undefined
		);
	}
}

const DEFAULT_LIST_COUNT = 50;

/*
 * The list's query as the store's filter. `active` is the people who can sign in as far as status goes —
 * active and not locked — so the three statuses read as a person would sort them, with a deactivated and
 * locked account under both of the other two.
 */
function listFilterOf(query: typeof UserListQuery.static): EndUserFilter {
	const filter: EndUserFilter = {};
	const q = query.q?.trim();
	if (q) filter.search = q;
	if (query.status === 'active') {
		filter.active = true;
		filter.locked = false;
	} else if (query.status === 'deactivated') {
		filter.active = false;
	} else if (query.status === 'locked') {
		filter.locked = true;
	}
	if (query.managedBy === 'console') filter.local = true;
	else if (query.managedBy !== undefined)
		filter.provisionedBy = query.managedBy;
	if (query.verified !== undefined) filter.verified = query.verified === 'yes';
	if (query.authenticator !== undefined)
		filter.totpEnrolled = query.authenticator === 'yes';
	return filter;
}

/* One person with their groups, as a row of the list is. */
async function presentOne(bucketId: string, user: User) {
	const [row] = await withGroups(bucketId, [user]);
	return row;
}

const NOT_CONFIGURED =
	'Mail delivery is not configured, so no message can be sent.';
const RATE_LIMITED = 'A message was sent recently. Try again in a minute.';

export const endUserRoutes = new Elysia({ name: 'admin-users-end' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	/*
	 * A page of the bucket's people, ordered by email, with how many match. Searched by the start of an email or
	 * a username in any letter case, or by an exact id, and narrowed by status, who manages them, verification
	 * and authenticator — every filter answered by the datastore, so a bucket of any size reads in one page.
	 */
	.get(
		'/admin/api/buckets/:id/users',
		async ({ admin, params, query, request }) => {
			const ctx = assertAuth(admin);
			await loadBucketForUsers(ctx, params.id);
			assertNoUnknownParams(request.url);
			const { users, totalResults } = await getUserStore(params.id).query(
				listFilterOf(query),
				{
					startIndex: Number(query.startIndex ?? 1),
					count: Number(query.count ?? DEFAULT_LIST_COUNT)
				},
				'email'
			);
			return { users: await withGroups(params.id, users), totalResults };
		},
		{ query: UserListQuery }
	)
	/*
	 * One person: the list's row, and — when they are locked — the email of the administrator who locked
	 * them, read now from the administrators' store, so an account since deleted reads as `null` rather than
	 * as an id nobody can place.
	 */
	.get('/admin/api/buckets/:id/users/:uid', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		await loadBucketForUsers(ctx, params.id);
		const user = await getUserStore(params.id).find(params.uid);
		if (!user) throw new AdminError(404, 'user not found');
		const row = await presentOne(params.id, user);
		if (!user.lockedLocally) return row;
		const locker = await getUserStore(ADMIN_BUCKET_ID).find(
			user.lockedLocally.by
		);
		return {
			...row,
			lockedLocally: {
				...user.lockedLocally,
				byEmail: locker?.email ?? null
			}
		};
	})
	.post(
		'/admin/api/buckets/:id/users',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
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
						// The bucket's policy, as registration applies it: an address nobody has proven is not
						// verified because an administrator typed it.
						verified: !bucket.emailVerificationRequired,
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
			const ctx = assertAuth(admin);
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
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const signOut = body.signOut === true;
			const { revoked } = await asAdmin(
				resetEndUserPassword(
					bucket,
					ADMIN,
					params.uid,
					body.password,
					() =>
						// The reset is the recorded fact; the password is never named, and its value never near
						// the trail. `signOut` is, because ending every sign-in is a second act the entry must show.
						recordAdminAudit(ctx, 'enduser.password.reset', params.uid, {
							targetScope: params.id,
							...(signOut ? { attributes: ['signOut'] } : {})
						}),
					{ signOut }
				)
			);
			if (revoked && revoked.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`the password was set, but their access survives in: ${revoked.failedAreas.join(', ')}`,
					{ failedAreas: revoked.failedAreas }
				);
			}
			return { ok: true };
		},
		{ body: ResetPasswordBody }
	)
	/*
	 * A new login address for a person administrators manage. Refused for a directory's person (the directory
	 * owns the address) and for an address another account in the bucket holds — both before the entry is
	 * written. The new address is unverified, and a message sent to the old one no longer verifies anything.
	 * The entry names the field, never the addresses: they are personal data, and the trail outlives the account.
	 */
	.post(
		'/admin/api/buckets/:id/users/:uid/email',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const { user } = await asAdmin(
				updateEndUser(bucket, ADMIN, params.uid, { email: body.email }, () =>
					recordAdminAudit(ctx, 'enduser.email.change', params.uid, {
						targetScope: params.id,
						attributes: ['email']
					})
				)
			);
			return presentOne(params.id, user);
		},
		{ body: ChangeEndUserEmailBody }
	)
	/*
	 * Mails the person a fresh verification message in the bucket's current method, within the cooldown and
	 * daily cap every other door shares. The answer never carries the link or the code: proving the address is
	 * the mailbox holder's act, not the administrator's. Every refusal that can be known first is decided
	 * before the entry, so the trail records sends that were attempted.
	 */
	.post(
		'/admin/api/buckets/:id/users/:uid/verification',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const user = await getUserStore(params.id).find(params.uid);
			if (!user) throw new AdminError(404, 'user not found');
			if (user.verified) {
				throw new AdminError(409, 'The address is already verified.');
			}
			if (!(await mailDeliveryConfigured())) {
				throw new AdminError(409, NOT_CONFIGURED);
			}
			if (await sendRateRefused(user, bucket)) {
				throw new AdminError(429, RATE_LIMITED);
			}
			await recordAdminAudit(ctx, 'enduser.verification.send', params.uid, {
				targetScope: params.id
			});
			const sent = await sendOnDemand(user, bucket, {
				reuseOutstanding: false
			});
			switch (sent.outcome) {
				case 'sent':
				case 'outstanding':
					set.status = 204;
					return;
				case 'rate_limited':
					throw new AdminError(429, RATE_LIMITED);
				case 'mail_not_configured':
					throw new AdminError(409, NOT_CONFIGURED);
				case 'delivery_failed':
					throw new AdminError(
						502,
						'The message could not be sent. Try again later.'
					);
			}
		}
	)
	/*
	 * The emergency block: ends the user's access at once and holds until an administrator lifts it, whatever
	 * the user's provisioning connection sends. The reason lives on the record, not in the trail.
	 */
	.post(
		'/admin/api/buckets/:id/users/:uid/lock',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
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
			const ctx = assertAuth(admin);
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
	 * Sign out everywhere: the user's access ends exactly as a lock would end it, but the account is left
	 * as it was — active, unlocked, free to sign in again. The answer to a stolen laptop rather than a
	 * compromised person, and what a bucket's upstream identity provider can also ask for (specs/072).
	 */
	.post(
		'/admin/api/buckets/:id/users/:uid/sign-out',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const { user, revoked } = await asAdmin(
				revokeEndUserAccess(bucket, params.uid, () =>
					recordAdminAudit(ctx, 'enduser.signout', params.uid, {
						targetScope: params.id
					})
				)
			);
			if (revoked && revoked.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`the user was signed out, but their access survives in: ${revoked.failedAreas.join(', ')}`,
					{ failedAreas: revoked.failedAreas }
				);
			}
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
			const ctx = assertAuth(admin);
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
		const ctx = assertAuth(admin);
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
