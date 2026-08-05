import { Elysia } from 'elysia';

import { getUserStore } from '../../adapters/index.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { CreateProviderBody, UpdateProviderBody } from './schema.js';
import {
	createProvider,
	deleteProvider,
	presentAll,
	present,
	updateProvider
} from './service.js';

/*
 * Managing a bucket's upstream providers, and severing an account's link to one.
 *
 * Access and the reserved-admin-bucket refusal are **inherited**, not re-implemented: `loadBucketForEdit`
 * and `loadBucketForUsers` already refuse `ADMIN_BUCKET_ID` with 403 and already apply bucket-manager
 * scoping. Writing an explicit check in each of six handlers would be six chances to forget one.
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
	.get('/admin/api/buckets/:id/federation', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const bucket = await loadBucketForUsers(ctx, params.id);
		return presentAll(bucket);
	})
	.post(
		'/admin/api/buckets/:id/federation',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			/*
			 * Recorded before the write, and after the validation that can refuse it: an entry for a request a
			 * 422 rejected would describe a provider that was never configured. The read surface already says
			 * an entry means an authorized actor reached the point of applying a change, not that it landed.
			 */
			await recordAdminAudit(ctx, 'federation.provider.create', params.id, {
				attributes: Object.keys(body)
			});
			const created = await createProvider(bucket, body);
			set.status = 201;
			return present(created);
		},
		{ body: CreateProviderBody }
	)
	.patch(
		'/admin/api/buckets/:id/federation/:providerId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await recordAdminAudit(ctx, 'federation.provider.update', params.id, {
				attributes: Object.keys(body)
			});
			return present(await updateProvider(bucket, params.providerId, body));
		},
		{ body: UpdateProviderBody }
	)
	.delete(
		'/admin/api/buckets/:id/federation/:providerId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await recordAdminAudit(ctx, 'federation.provider.delete', params.id);
			await deleteProvider(bucket, params.providerId);
			return { ok: true };
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
		'/admin/api/buckets/:id/users/:uid/identities',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForUsers(ctx, params.id);
			const user = await getUserStore(params.id).find(params.uid);
			if (!user) throw new AdminError(404, 'user not found');
			// Provider, subject and when — no credential, and nothing about the provider's configuration.
			return user.federated ?? [];
		}
	)
	.delete(
		'/admin/api/buckets/:id/users/:uid/identities/:providerId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForUsers(ctx, params.id);
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
				targetScope: params.id
			});
			await store.update(params.uid, { federated });
			return { ok: true };
		}
	);
