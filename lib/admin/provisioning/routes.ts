import { Elysia, t } from 'elysia';

import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { presentUser } from '../users-end/routes.js';
import {
	assignEndUserToConnection,
	EndUserError
} from '../../end_users/service.js';
import {
	createConnection,
	deleteConnection,
	issueCredential,
	loadConnection,
	managedUserCount,
	presentConnection,
	ProvisioningError,
	releaseConnection,
	revokeCredential,
	updateConnection
} from '../../provisioning/service.js';
import {
	getBucketStore,
	getProvisioningConnectionStore
} from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	AssignConnectionBody,
	CreateConnectionBody,
	CredentialKindParam,
	IssueCredentialBody,
	UpdateConnectionBody
} from './schema.js';

/*
 * A bucket's SCIM provisioning connections, and handing a local user to one.
 *
 * Reads are open to whoever may manage the bucket's users; every write needs the bucket itself
 * (`loadBucketForEdit`), because a connection decides who may create people in it. Both refuse the
 * administrators' bucket. Every write records audit-first, after authorization and after every refusal —
 * the service calls `record` at exactly that point, so a refused request leaves no entry.
 *
 * Not behind `scim.enabled`, for federation's reason: a connection must be preparable before the capability
 * is switched on, and removable after it is switched off.
 */

async function asAdmin<T>(operation: Promise<T>): Promise<T> {
	try {
		return await operation;
	} catch (error) {
		if (error instanceof ProvisioningError) {
			throw new AdminError(error.status, error.message, error.extra);
		}
		if (error instanceof EndUserError) {
			throw new AdminError(error.status, error.message);
		}
		throw error;
	}
}

function scope(bucket: UserBucket) {
	return { targetScope: bucket._id, ownerGroupId: bucket.ownerGroupId };
}

async function view(bucket: UserBucket, connectionId: string) {
	const connection = await loadConnection(bucket, connectionId);
	return presentConnection(
		bucket,
		connection,
		await managedUserCount(bucket._id, connection._id)
	);
}

export const provisioningRoutes = new Elysia({ name: 'admin-provisioning' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/buckets/:id/provisioning-connections',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const connections = await getProvisioningConnectionStore().listByBucket(
				bucket._id
			);
			return Promise.all(
				connections.map(async (c) =>
					presentConnection(
						bucket,
						c,
						await managedUserCount(bucket._id, c._id)
					)
				)
			);
		}
	)
	.get(
		'/admin/api/buckets/:id/provisioning-connections/:connectionId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			return asAdmin(view(bucket, params.connectionId));
		}
	)
	.post(
		'/admin/api/buckets/:id/provisioning-connections',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const created = await asAdmin(
				createConnection(bucket, body, async () => {
					/*
					 * The connection's id is allocated by the store, so the entry names the provider it binds;
					 * the bucket travels as the scope. `attributes` are field names, never values.
					 */
					await recordAdminAudit(
						ctx,
						'provisioning.connection.create',
						body.providerId,
						{ attributes: Object.keys(body), ...scope(bucket) }
					);
				})
			);
			set.status = 201;
			/* Re-read: creating the connection also closed its provider to just-in-time creation. */
			const updated = (await getBucketStore().find(bucket._id)) ?? bucket;
			return asAdmin(view(updated, created._id));
		},
		{ body: CreateConnectionBody }
	)
	.patch(
		'/admin/api/buckets/:id/provisioning-connections/:connectionId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await asAdmin(
				updateConnection(bucket, params.connectionId, body, () =>
					recordAdminAudit(
						ctx,
						'provisioning.connection.update',
						params.connectionId,
						{ attributes: Object.keys(body), ...scope(bucket) }
					)
				)
			);
			return asAdmin(view(bucket, params.connectionId));
		},
		{ body: UpdateConnectionBody }
	)
	.delete(
		'/admin/api/buckets/:id/provisioning-connections/:connectionId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const result = await asAdmin(
				deleteConnection(bucket, params.connectionId, () =>
					recordAdminAudit(
						ctx,
						'provisioning.connection.delete',
						params.connectionId,
						scope(bucket)
					)
				)
			);
			/* The connection is gone either way; a token area left behind is reported, as a client delete does. */
			if (result.failedAreas.length > 0) {
				throw new AdminError(
					500,
					'connection deleted, but some of its tokens could not be revoked',
					{ failedAreas: [...result.failedAreas] }
				);
			}
			return { ok: true };
		}
	)
	/*
	 * Ends a mass-deprovisioning hold and restarts the count: the directory's next retries go through. The
	 * bucket's edit right, as every other connection write, because what it re-admits is the deprovisioning of
	 * the bucket's people. 409 when the connection is not held.
	 */
	.post(
		'/admin/api/buckets/:id/provisioning-connections/:connectionId/release',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await asAdmin(
				releaseConnection(bucket, params.connectionId, () =>
					recordAdminAudit(
						ctx,
						'provisioning.connection.release',
						params.connectionId,
						scope(bucket)
					)
				)
			);
			return asAdmin(view(bucket, params.connectionId));
		}
	)
	/*
	 * The one response that ever carries a connection's secret or static token — shown once, for the
	 * administrator to paste into the directory. The audit entry records the kind, never the value.
	 */
	.post(
		'/admin/api/buckets/:id/provisioning-connections/:connectionId/credentials',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const issued = await asAdmin(
				issueCredential(bucket, params.connectionId, body, () =>
					recordAdminAudit(
						ctx,
						'provisioning.credential.issue',
						params.connectionId,
						{ attributes: [body.kind], ...scope(bucket) }
					)
				)
			);
			set.status = 201;
			return {
				connection: await asAdmin(view(bucket, params.connectionId)),
				...(issued.secret ? { secret: issued.secret } : {}),
				...(issued.token ? { token: issued.token } : {})
			};
		},
		{ body: IssueCredentialBody }
	)
	.delete(
		'/admin/api/buckets/:id/provisioning-connections/:connectionId/credentials/:kind',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await asAdmin(
				revokeCredential(bucket, params.connectionId, params.kind, () =>
					recordAdminAudit(
						ctx,
						'provisioning.credential.revoke',
						params.connectionId,
						{ attributes: [params.kind], ...scope(bucket) }
					)
				)
			);
			return asAdmin(view(bucket, params.connectionId));
		},
		{
			params: t.Object({
				id: t.String(),
				connectionId: t.String(),
				kind: CredentialKindParam
			})
		}
	)
	/*
	 * `:uid` at this position, because the end-user routes already name the slot so and the router refuses
	 * two names for one slot.
	 */
	.post(
		'/admin/api/buckets/:id/users/:uid/connection',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await asAdmin(loadConnection(bucket, body.connectionId));
			const assigned = await asAdmin(
				assignEndUserToConnection(
					bucket,
					params.uid,
					{
						connectionId: body.connectionId,
						userName: body.userName,
						externalId: body.externalId
					},
					() =>
						recordAdminAudit(ctx, 'enduser.connection.assign', params.uid, {
							attributes: Object.keys(body),
							...scope(bucket)
						})
				)
			);
			return presentUser(assigned);
		},
		{ body: AssignConnectionBody }
	);
