import { Elysia } from 'elysia';

import { getUserStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import {
	loadBucketForProviders,
	loadBucketForUsers
} from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { ADMIN_SESSION_COOKIE } from '../consts.js';
import { issuingBucket } from '../auth/bucketAddress.js';
import {
	CreateProviderBody,
	MoveProviderBody,
	UpdateProviderBody
} from './schema.js';
import { guidanceForBucket } from './guidance.js';
import {
	createProvider,
	deleteProvider,
	findProvider,
	moveProvider,
	plannedMove,
	presentAll,
	present,
	presentDetail,
	updateProvider
} from './service.js';
import { DiscoveryError } from '../../federation/discovery.js';
import { authorizationUrl, supportsPkce } from '../../federation/flow.js';
import { federationEnabled } from '../../federation/providers.js';
import { openTry, readTry, sessionDigestOf } from '../../federation/state.js';
import type { TryStarted, TryStatus } from '../../federation/types.js';
import { upstreamMetadata } from '../../federation/upstream.js';

/* The console session cookie's value, read as the scope route reads it; absent for an agent's bearer token. */
function sessionCookieOf(
	cookie: Record<string, { value?: unknown }>
): string | undefined {
	const value = cookie[ADMIN_SESSION_COOKIE].value;
	return typeof value === 'string' && value ? value : undefined;
}

/*
 * The team an entry belongs to, which is the only thing a team's read of the trail selects on. Without it a
 * project's provider changes were visible to super administrators alone, while its team read every other
 * change to the same project.
 */
function ownedBy(bucket: Pick<UserBucket, 'ownerGroupId'>): {
	ownerGroupId: string;
} {
	return { ownerGroupId: bucket.ownerGroupId };
}

/*
 * Managing a bucket's upstream providers, and severing an account's link to one.
 *
 * Access is **inherited** from the loaders, not re-implemented in each handler. The providers use
 * `loadBucketForProviders`, which admits the administrators' bucket for a super administrator only
 * (specs/080); the identities use `loadBucketForUsers`, which keeps refusing it — an administrator's links
 * are not managed from the bucket page.
 *
 * Every mutation is audit-first — after authorization, before the write — with `attributes` naming the
 * fields the request set and never their values, so a `clientSecret` change records the name and nothing
 * more.
 *
 * These routes are deliberately **not** behind `federation.enabled`. A provider must be configurable before
 * the capability is switched on, and — the case that decides it — deletable by a deployment that has just
 * switched it off.
 */
export const federationAdminRoutes = new Elysia({ name: 'admin-federation' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/projects/:id/federation', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForProviders(ctx, params.id, 'read');
		return presentAll(bucket);
	})
	/*
	 * What it takes to connect a recognised provider to this bucket — including the callback address to
	 * register, which depends on the bucket's own address and has never been visible anywhere in the
	 * console. Ungated and unaudited for the same reasons as its siblings: a read records nothing, and an
	 * administrator preparing a connection needs this before the capability is switched on.
	 */
	.get(
		'/admin/api/projects/:id/federation/catalogue',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForProviders(ctx, params.id, 'read');
			return { providers: guidanceForBucket(bucket) };
		}
	)
	/*
	 * One provider, with what its page explains (specs/084 R1): its callback, the logout signals it can send and
	 * whether this instance accepts them, the provisioning connection bound to it and how many people are
	 * linked to it. Read with the list's right; the secrets are masked as in the list.
	 */
	.get(
		'/admin/api/projects/:id/federation/:providerId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForProviders(ctx, params.id, 'read');
			return presentDetail(bucket, params.providerId);
		}
	)
	.post(
		'/admin/api/projects/:id/federation',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForProviders(ctx, params.id, 'edit');
			/*
			 * Recorded before the write, and after the validation that can refuse it: an entry for a request a
			 * 422 rejected would describe a provider that was never configured. The read surface already says
			 * an entry means an authorized actor reached the point of applying a change, not that it landed.
			 */
			await recordAdminAudit(ctx, 'federation.provider.create', params.id, {
				attributes: Object.keys(body),
				...ownedBy(bucket)
			});
			const created = await createProvider(bucket, ctx, body);
			set.status = 201;
			return present(created, bucket);
		},
		{ body: CreateProviderBody }
	)
	.patch(
		'/admin/api/projects/:id/federation/:providerId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForProviders(ctx, params.id, 'edit');
			await recordAdminAudit(ctx, 'federation.provider.update', params.id, {
				attributes: Object.keys(body),
				...ownedBy(bucket)
			});
			return present(
				await updateProvider(bucket, ctx, params.providerId, body),
				bucket
			);
		},
		{ body: UpdateProviderBody }
	)
	.delete(
		'/admin/api/projects/:id/federation/:providerId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForProviders(ctx, params.id, 'edit');
			await recordAdminAudit(
				ctx,
				'federation.provider.delete',
				params.id,
				ownedBy(bucket)
			);
			await deleteProvider(bucket, ctx, params.providerId);
			return { ok: true };
		}
	)
	/*
	 * One place up or down in the order the bucket's sign-in page shows its buttons (specs/088 R10). Writes
	 * the order and nothing else; refused (409) at an end. The entry records the order before and after.
	 */
	.post(
		'/admin/api/projects/:id/federation/:providerId/move',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForProviders(ctx, params.id, 'edit');
			const { from, to } = plannedMove(
				bucket,
				ctx,
				params.providerId,
				body.direction
			);
			await recordAdminAudit(ctx, 'federation.provider.move', params.id, {
				attributes: [params.providerId],
				from: from.join(', '),
				to: to.join(', '),
				...ownedBy(bucket)
			});
			const moved = await moveProvider(bucket, to);
			return { providers: presentAll(moved) };
		},
		{ body: MoveProviderBody }
	)
	/*
	 * Try a sign-in through a provider before anyone depends on it (specs/088 R6): the answer is the address
	 * to open in a new tab, where the administrator signs in at the provider; the result is read below. The
	 * provider is found whether or not it is enabled. Bound to this console session — a request with no
	 * session (an agent's) is refused, because nobody could read the result. Audited at the start; the
	 * result is not recorded.
	 */
	.post(
		'/admin/api/projects/:id/federation/:providerId/try',
		async ({ admin, params, cookie, set }): Promise<TryStarted> => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForProviders(ctx, params.id, 'edit');
			const provider = findProvider(bucket, params.providerId);
			const session = sessionCookieOf(cookie);
			if (!session) {
				throw new AdminError(
					403,
					'a try needs a console session in a browser, where its result is shown'
				);
			}
			if (!federationEnabled()) {
				throw new AdminError(
					409,
					'federation is switched off on this instance (federation.enabled), so there is nothing to try'
				);
			}
			let metadata;
			try {
				metadata = await upstreamMetadata(provider);
			} catch (err) {
				if (err instanceof DiscoveryError) {
					throw new AdminError(
						502,
						`could not read the discovery document at ${provider.issuer}`
					);
				}
				throw err;
			}
			await recordAdminAudit(ctx, 'federation.provider.try', params.id, {
				attributes: [provider.id],
				...ownedBy(bucket)
			});
			const opened = await openTry({
				bucketId: bucket._id,
				providerId: provider.id,
				sessionDigest: sessionDigestOf(session),
				withPkce: supportsPkce(metadata, provider)
			});
			set.status = 201;
			return {
				tryRef: opened.tryRef,
				authorizationUrl: authorizationUrl(
					provider,
					metadata,
					opened,
					await issuingBucket(bucket._id)
				),
				expiresAt: opened.expiresAt.toISOString()
			};
		}
	)
	/*
	 * A try's result, for the console session that started it: `waiting` until the provider has sent the
	 * browser back, then `done` with what it answered and what a real sign-in would do. Every mismatch — another
	 * session, bucket or provider, an unknown or expired try — is the same 404.
	 */
	.get(
		'/admin/api/projects/:id/federation/:providerId/try/:tryRef',
		async ({ admin, params, cookie }): Promise<TryStatus> => {
			const ctx = assertAuth(admin);
			await loadBucketForProviders(ctx, params.id, 'read');
			const session = sessionCookieOf(cookie);
			const record = session
				? await readTry(params.tryRef, sessionDigestOf(session))
				: null;
			if (
				!record ||
				record.bucketId !== params.id ||
				record.providerId !== params.providerId
			) {
				throw new AdminError(404, 'try not found');
			}
			return record.result
				? { status: 'done', result: record.result }
				: { status: 'waiting' };
		}
	)
	/*
	 * The identities half. `loadBucketForUsers` rather than `loadBucketForEdit`: severing a link is an
	 * operation on a bucket's *users*, which a bucket manager may perform, not a change to the bucket entity.
	 */
	/*
	 * `:uid`, not `:userId`: the existing end-user routes already use that name at this position, and the
	 * router refuses two different parameter names in the same slot outright.
	 */
	.get(
		'/admin/api/projects/:id/users/:uid/identities',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			await loadBucketForUsers(ctx, params.id);
			const user = await getUserStore(params.id).find(params.uid);
			if (!user) throw new AdminError(404, 'user not found');
			// Provider, subject and when — no credential, and nothing about the provider's configuration.
			return user.federated ?? [];
		}
	)
	.delete(
		'/admin/api/projects/:id/users/:uid/identities/:providerId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const store = getUserStore(params.id);
			const user = await store.find(params.uid);
			if (!user) throw new AdminError(404, 'user not found');

			const federated = (user.federated ?? []).filter(
				(link) => link.providerId !== params.providerId
			);
			if (federated.length === (user.federated ?? []).length) {
				throw new AdminError(404, 'identity not found');
			}

			/*
			 * `targetScope` carries the bucket, as it does for every other end-user row: these accounts live in
			 * per-bucket storage, so a bare user id cannot be resolved to an account — not even to an email —
			 * without knowing which bucket to look in.
			 */
			await recordAdminAudit(ctx, 'federation.identity.delete', params.uid, {
				targetScope: params.id,
				...ownedBy(bucket)
			});
			await store.update(params.uid, { federated });
			return { ok: true };
		}
	);
