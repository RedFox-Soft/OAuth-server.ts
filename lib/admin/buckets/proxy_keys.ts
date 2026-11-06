import { Elysia } from 'elysia';

import { getBucketStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	forgetProxyKeys,
	MAX_PROXY_KEYS,
	newProxyKey
} from '../../behind_proxy/proxy_key.js';
import { recordAdminAudit } from '../audit/record.js';
import {
	AdminError,
	adminErrorBody,
	assertAuth,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit } from './access.js';
import { scheduledBucketGuard } from './scheduled_guard.js';
import { IssueProxyKeyBody } from './schema.js';

/*
 * A project's proxy keys (specs/124 research R5): what the operator's proxy presents so that the person's address it
 * reports is believed. Issuing answers the key once and never again — so it is the console's alone, never an agent's —
 * while listing and withdrawing are published to MCP. Every write needs the project itself, and is recorded before it
 * takes effect.
 */

function listed(bucket: Pick<UserBucket, 'proxyKeys'>) {
	return {
		keys: (bucket.proxyKeys ?? []).map((key) => ({
			id: key.id,
			createdAt: key.createdAt.toISOString()
		}))
	};
}

export const proxyKeyRoutes = new Elysia({ name: 'admin-proxy-keys' })
	.use(resolveAdmin)
	.use(scheduledBucketGuard)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/projects/:id/proxy-keys', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		return listed(await loadBucketForEdit(ctx, params.id));
	})
	.post(
		'/admin/api/projects/:id/proxy-keys',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const keys = bucket.proxyKeys ?? [];
			if (keys.length >= MAX_PROXY_KEYS) {
				throw new AdminError(
					409,
					'This project already has two proxy keys. Withdraw the one your proxy no longer uses, then issue a new one.',
					{ code: 'proxy_key_limit' }
				);
			}
			const issued = newProxyKey();
			await recordAdminAudit(ctx, 'bucket.proxykey.issue', bucket._id, {
				ownerGroupId: bucket.ownerGroupId,
				kid: issued.id
			});
			const createdAt = new Date();
			await getBucketStore().update(bucket._id, {
				proxyKeys: [
					...keys,
					{ id: issued.id, digest: issued.digest, createdAt }
				]
			});
			forgetProxyKeys(bucket._id);
			set.status = 201;
			return {
				id: issued.id,
				createdAt: createdAt.toISOString(),
				key: issued.key
			};
		},
		{ body: IssueProxyKeyBody }
	)
	.delete(
		'/admin/api/projects/:id/proxy-keys/:keyId',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const keys = bucket.proxyKeys ?? [];
			if (!keys.some((key) => key.id === params.keyId)) {
				throw new AdminError(404, 'no such proxy key');
			}
			await recordAdminAudit(ctx, 'bucket.proxykey.withdraw', bucket._id, {
				ownerGroupId: bucket.ownerGroupId,
				kid: params.keyId
			});
			await getBucketStore().update(bucket._id, {
				proxyKeys: keys.filter((key) => key.id !== params.keyId)
			});
			forgetProxyKeys(bucket._id);
			set.status = 204;
		}
	);
