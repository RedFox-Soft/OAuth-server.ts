import { Elysia } from 'elysia';

import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { scheduledBucketGuard } from '../buckets/scheduled_guard.js';
import { recordAdminAudit } from '../audit/record.js';
import { getBehindProxyAppStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	createApp,
	deleteApp,
	loadApp,
	updateApp,
	viewApp,
	viewApps
} from './service.js';
import {
	CreateBehindProxyAppBody,
	UpdateBehindProxyAppBody
} from './schema.js';

/*
 * A project's apps behind a proxy (specs/122): web apps the operator's own proxy asks this server about before
 * letting a request through. Reads are open to whoever may manage the project's people, who are the ones the
 * rules name; every write needs the project itself (`loadBucketForEdit`), because an app's rules decide who
 * reaches it. Both loaders refuse the administrators' project. Every write is recorded before it takes effect
 * and after every refusal, by the service calling `record` at that point.
 */

function scope(bucket: UserBucket) {
	return { targetScope: bucket._id, ownerGroupId: bucket.ownerGroupId };
}

export const behindProxyRoutes = new Elysia({ name: 'admin-behind-proxy' })
	.use(resolveAdmin)
	/*
	 * Mounted as a statement of its own (lib/admin/routes.ts, for the type-depth reason given there), so the chain's
	 * guard does not reach these routes: a write into a bucket scheduled for deletion is refused here as everywhere.
	 */
	.use(scheduledBucketGuard)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/projects/:id/behind-proxy', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForUsers(ctx, params.id);
		const apps = await getBehindProxyAppStore().listByBucket(bucket._id);
		return { apps: await viewApps(bucket, apps) };
	})
	.get(
		'/admin/api/projects/:id/behind-proxy/:appId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			return viewApp(bucket, await loadApp(bucket, params.appId));
		}
	)
	.post(
		'/admin/api/projects/:id/behind-proxy',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const created = await createApp(bucket, body, (appId) =>
				recordAdminAudit(ctx, 'behindproxy.create', appId, {
					attributes: Object.keys(body),
					...scope(bucket)
				})
			);
			set.status = 201;
			return viewApp(bucket, created);
		},
		{ body: CreateBehindProxyAppBody }
	)
	.patch(
		'/admin/api/projects/:id/behind-proxy/:appId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const updated = await updateApp(bucket, params.appId, body, () =>
				recordAdminAudit(ctx, 'behindproxy.update', params.appId, {
					attributes: Object.keys(body),
					...scope(bucket)
				})
			);
			return viewApp(bucket, updated);
		},
		{ body: UpdateBehindProxyAppBody }
	)
	.delete(
		'/admin/api/projects/:id/behind-proxy/:appId',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await deleteApp(bucket, params.appId, () =>
				recordAdminAudit(ctx, 'behindproxy.delete', params.appId, scope(bucket))
			);
			set.status = 204;
		}
	);
