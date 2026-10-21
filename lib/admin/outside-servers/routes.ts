import { Elysia } from 'elysia';

import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { getOutsideAuthorizationServerStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	createOutsideServer,
	deleteOutsideServer,
	loadOutsideServer,
	updateOutsideServer,
	viewOutsideServer
} from './service.js';
import { CreateOutsideServerBody, UpdateOutsideServerBody } from './schema.js';

/*
 * A project's outside authorization servers (specs/108): the servers it vouches for its people to with
 * ID-JAGs. Reads are open to whoever may manage the project's people; every write needs the project itself
 * (`loadBucketForEdit`), because a connection decides to whom the project vouches for them. Every write is
 * recorded before it takes effect and after every refusal, by the service calling `record` at that point.
 *
 * Not behind `tokenExchange.enabled`: a connection must be preparable before the grant is switched on, and
 * removable after it is switched off — and that removal recorded.
 */

function scope(bucket: UserBucket) {
	return { targetScope: bucket._id, ownerGroupId: bucket.ownerGroupId };
}

export const outsideServerRoutes = new Elysia({ name: 'admin-outside-servers' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/projects/:id/outside-authorization-servers',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const records = await getOutsideAuthorizationServerStore().listByBucket(
				bucket._id
			);
			return Promise.all(records.map(viewOutsideServer));
		}
	)
	.get(
		'/admin/api/projects/:id/outside-authorization-servers/:serverId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			return viewOutsideServer(
				await loadOutsideServer(bucket, params.serverId)
			);
		}
	)
	.post(
		'/admin/api/projects/:id/outside-authorization-servers',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const created = await createOutsideServer(bucket, body, (serverId) =>
				recordAdminAudit(ctx, 'outside.server.create', serverId, {
					attributes: Object.keys(body),
					...scope(bucket)
				})
			);
			set.status = 201;
			return viewOutsideServer(created);
		},
		{ body: CreateOutsideServerBody }
	)
	.patch(
		'/admin/api/projects/:id/outside-authorization-servers/:serverId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const updated = await updateOutsideServer(
				bucket,
				params.serverId,
				body,
				() =>
					recordAdminAudit(ctx, 'outside.server.update', params.serverId, {
						attributes: Object.keys(body),
						...scope(bucket)
					})
			);
			return viewOutsideServer(updated);
		},
		{ body: UpdateOutsideServerBody }
	)
	.delete(
		'/admin/api/projects/:id/outside-authorization-servers/:serverId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await deleteOutsideServer(bucket, params.serverId, () =>
				recordAdminAudit(
					ctx,
					'outside.server.delete',
					params.serverId,
					scope(bucket)
				)
			);
			return { ok: true };
		}
	);
