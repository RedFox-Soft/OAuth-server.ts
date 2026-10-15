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
	ProvisioningError,
	readHold,
	releaseConnection,
	retirePreviousCredential,
	revokeCredential,
	updateConnection,
	viewConnection
} from '../../provisioning/service.js';
import {
	getBucketStore,
	getProvisioningConnectionStore
} from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { directoryGuidance } from './directories.js';
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
	return viewConnection(bucket, await loadConnection(bucket, connectionId));
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
		'/admin/api/projects/:id/provisioning-connections',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const connections = await getProvisioningConnectionStore().listByBucket(
				bucket._id
			);
			return Promise.all(connections.map((c) => viewConnection(bucket, c)));
		}
	)
	/*
	 * What it takes to connect each known directory to this bucket, in that directory's own words (specs/088
	 * R9): the same facts the console's wizard shows, so an agent configuring Entra or Okta reads them too.
	 */
	.get(
		'/admin/api/projects/:id/provisioning-connections/directories',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			return { directories: directoryGuidance(bucket) };
		}
	)
	.get(
		'/admin/api/projects/:id/provisioning-connections/:connectionId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			return asAdmin(view(bucket, params.connectionId));
		}
	)
	/*
	 * Whom a held connection has been refused the removal of, in this hold — what an administrator reads
	 * before releasing it, because the release lets the directory's retries of exactly these go through
	 * (specs/084 R2). `{held: false}` for a connection that is not held.
	 */
	.get(
		'/admin/api/projects/:id/provisioning-connections/:connectionId/hold',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			return asAdmin(readHold(bucket, params.connectionId));
		}
	)
	.post(
		'/admin/api/projects/:id/provisioning-connections',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const created = await asAdmin(
				createConnection(bucket, body, async (connectionId) => {
					/*
					 * The connection the entry creates, as every later entry about it is targeted (specs/085); entries
					 * written before named the provider it binds. The bucket travels as the scope. `attributes` are
					 * field names, never values.
					 */
					await recordAdminAudit(
						ctx,
						'provisioning.connection.create',
						connectionId,
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
		'/admin/api/projects/:id/provisioning-connections/:connectionId',
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
		'/admin/api/projects/:id/provisioning-connections/:connectionId',
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
		'/admin/api/projects/:id/provisioning-connections/:connectionId/release',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await asAdmin(
				releaseConnection(bucket, params.connectionId, (refusedRemovals) =>
					recordAdminAudit(
						ctx,
						'provisioning.connection.release',
						params.connectionId,
						{
							...scope(bucket),
							/* How many people's removals the release re-admits; absent when it re-admits none. */
							...(refusedRemovals > 0 ? { cascade: { refusedRemovals } } : {})
						}
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
		'/admin/api/projects/:id/provisioning-connections/:connectionId/credentials',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const issued = await asAdmin(
				issueCredential(bucket, params.connectionId, body, (previousEndsAt) =>
					recordAdminAudit(
						ctx,
						'provisioning.credential.issue',
						params.connectionId,
						{
							attributes: [body.kind],
							/* Whether the replaced value overlaps, and until when at the latest (specs/088 FR-006). */
							to: previousEndsAt?.toISOString() ?? null,
							...scope(bucket)
						}
					)
				)
			);
			set.status = 201;
			return {
				connection: await asAdmin(view(bucket, params.connectionId)),
				...(issued.secret ? { secret: issued.secret } : {}),
				...(issued.token ? { token: issued.token } : {}),
				previousEndsAt: issued.previousEndsAt?.toISOString() ?? null
			};
		},
		{ body: IssueCredentialBody }
	)
	/*
	 * Ends a slot's overlapping previous value at once, with the tokens it obtained; the current value is
	 * untouched (specs/088). 404 when there is no previous value that still works.
	 */
	.delete(
		'/admin/api/projects/:id/provisioning-connections/:connectionId/credentials/:kind/previous',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			await asAdmin(
				retirePreviousCredential(bucket, params.connectionId, params.kind, () =>
					recordAdminAudit(
						ctx,
						'provisioning.credential.retire',
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
	.delete(
		'/admin/api/projects/:id/provisioning-connections/:connectionId/credentials/:kind',
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
		'/admin/api/projects/:id/users/:uid/connection',
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
