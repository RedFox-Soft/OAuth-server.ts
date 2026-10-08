import { Elysia, t } from 'elysia';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { GenerateBucketKeyBody } from './schema.js';
import {
	generateKey,
	KeyActionRefused,
	listKeys,
	promoteKey,
	retireKey
} from './service.js';
import { RetireKeyBody, type SupportedAlg } from '../jwks/schema.js';

/*
 * An addressable bucket's own signing keys. Authorization is the bucket's — its owning group, or a
 * super administrator — and resolved in the service, so the console and an agent reach the same check.
 */
export const bucketKeyRoutes = new Elysia({ name: 'admin-bucket-keys' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return error instanceof KeyActionRefused
				? { ...adminErrorBody(error), ...error.detail }
				: adminErrorBody(error);
		}
	})
	.get('/admin/api/buckets/:id/keys', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		return listKeys(ctx, params.id);
	})
	.post(
		'/admin/api/buckets/:id/keys',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const created = await generateKey(
				ctx,
				params.id,
				// The schema's union is built from SUPPORTED_ALGS, so the literal is one of them.
				body.alg as SupportedAlg
			);
			set.status = 201;
			return created;
		},
		{ body: GenerateBucketKeyBody }
	)
	.post(
		'/admin/api/buckets/:id/keys/:kid/promote',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			return promoteKey(ctx, params.id, params.kid);
		}
	)
	.delete(
		'/admin/api/buckets/:id/keys/:kid',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			return retireKey(ctx, params.id, params.kid, body?.confirm);
		},
		{ body: t.Optional(RetireKeyBody) }
	);
