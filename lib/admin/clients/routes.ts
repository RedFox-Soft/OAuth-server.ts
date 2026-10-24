import { Elysia } from 'elysia';
import { adapter } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { CreateClientBody, UpdateClientBody } from './schema.js';
import {
	createClient,
	getClientView,
	listClientView,
	updateClient,
	rotateSecret,
	deleteClientRecord,
	type AdminClientView
} from './service.js';
import { recordAdminAudit } from '../audit/record.js';
import { cascadeForClient } from '../../helpers/cascade.js';
import nanoid from '../../helpers/nanoid.js';
import { assertApplicationRoom } from '../../plans/enforce.js';
import { connectionOf } from './connection.js';
import { readClientUsage } from '../../models/client/usage.js';
import { parseClientIdentifierUrl } from '../../client_metadata_document/identifier.js';

/*
 * A bucket's applications (specs/099). The bucket is the only container: an application belongs to one
 * for its whole life, and every route here is addressed under it. Reading needs the bucket's read right,
 * changing needs its edit right — the administrators' bucket is closed to both, so its own clients are
 * never managed here.
 */
function loadBucket(
	ctx: AdminContext,
	id: string,
	mode: 'read' | 'edit'
): Promise<UserBucket> {
	return mode === 'read'
		? loadBucketForUsers(ctx, id)
		: loadBucketForEdit(ctx, id);
}

/*
 * The application under this bucket, answered exactly as a missing one when the bucket does not hold it,
 * so naming another bucket's application tells the caller nothing about it.
 */
async function clientOf(
	bucket: UserBucket,
	clientId: string
): Promise<AdminClientView> {
	const view = await getClientView(clientId);
	if (view?.projectId !== bucket._id) {
		throw new AdminError(404, 'client not found');
	}
	return view;
}

/*
 * A self-registered application is listed and readable here, but changed only through its own
 * registration access token: the administrator did not create it, and its consent setting in particular
 * must stay what the registration made it.
 */
function assertManaged(view: AdminClientView): void {
	if (view.registeredDynamically) {
		throw new AdminError(
			409,
			'this application registered itself and is managed through its registration access token'
		);
	}
}

/* The view with what an application needs to be configured, read the way the console and an agent both get it. */
async function connected(view: AdminClientView, bucket: UserBucket) {
	return {
		...view,
		connection: await connectionOf(
			view,
			bucket,
			await readClientUsage(view.clientId)
		)
	};
}

function scopeOf(bucket: UserBucket) {
	return { bucketId: bucket._id, ownerGroupId: bucket.ownerGroupId };
}

export const clientRoutes = new Elysia({ name: 'admin-clients' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/projects/:id/clients', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucket(ctx, params.id, 'read');
		const stored = await adapter('Client').findByIndexed(
			'bucketId',
			bucket._id
		);
		const views = [];
		for (const record of stored) {
			const view = await listClientView(String(record.clientId));
			if (view) {
				views.push({
					...view,
					lastUsed: await readClientUsage(view.clientId)
				});
			}
		}
		return views;
	})
	.post(
		'/admin/api/projects/:id/clients',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucket(ctx, params.id, 'edit');
			await assertApplicationRoom(ctx, bucket);
			const { clientIdentifierUrl, ...metadata } = body;
			// Allocated here so the entry names the client that is about to exist.
			const clientId = clientIdentifierUrl ?? nanoid();
			if (clientIdentifierUrl !== undefined) {
				const parsed = parseClientIdentifierUrl(clientIdentifierUrl);
				if (!parsed.ok) {
					throw new AdminError(
						422,
						`clientIdentifierUrl is not a Client Identifier URL (${parsed.reason})`,
						{ field: 'clientIdentifierUrl' }
					);
				}
				if (await adapter('Client').find(clientIdentifierUrl)) {
					throw new AdminError(
						409,
						'an application with that client id already exists',
						{ field: 'clientIdentifierUrl' }
					);
				}
			}
			await recordAdminAudit(ctx, 'client.create', clientId, scopeOf(bucket));
			const { view, secret } = await createClient(bucket._id, {
				...metadata,
				clientId
			});
			set.status = 201;
			return { ...(await connected(view, bucket)), secret };
		},
		{ body: CreateClientBody }
	)
	.get(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucket(ctx, params.id, 'read');
			return connected(await clientOf(bucket, params.clientId), bucket);
		}
	)
	.patch(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucket(ctx, params.id, 'edit');
			assertManaged(await clientOf(bucket, params.clientId));
			await recordAdminAudit(ctx, 'client.update', params.clientId, {
				...scopeOf(bucket),
				attributes: Object.keys(body)
			});
			const { view, secret } = await updateClient(params.clientId, body);
			return {
				...(await connected(view, bucket)),
				...(secret ? { secret } : {})
			};
		},
		{ body: UpdateClientBody }
	)
	.post(
		'/admin/api/projects/:id/clients/:clientId/secret',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucket(ctx, params.id, 'edit');
			assertManaged(await clientOf(bucket, params.clientId));
			// The rotation is the recorded fact; the secret itself never enters the trail.
			await recordAdminAudit(
				ctx,
				'client.secret.rotate',
				params.clientId,
				scopeOf(bucket)
			);
			const secret = await rotateSecret(params.clientId);
			return { clientId: params.clientId, secret };
		}
	)
	.delete(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucket(ctx, params.id, 'edit');
			assertManaged(await clientOf(bucket, params.clientId));
			await recordAdminAudit(
				ctx,
				'client.delete',
				params.clientId,
				scopeOf(bucket)
			);
			await deleteClientRecord(params.clientId);
			/*
			 * Audit, then destroy the principal, then cascade — the sweep runs after the record is gone, so
			 * the client is not usable while its tokens are being revoked.
			 *
			 * A sweep that fails partway is answered, not rolled back. The client is already gone, so a
			 * repeated DELETE answers 404, and the residue is bounded by each area's own TTL because the
			 * one area that can outlive a failure is swept first. Closing the door first is the point.
			 */
			const cascade = await cascadeForClient(params.clientId);
			if (cascade.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`client deleted, but its records survive in: ${cascade.failedAreas.join(', ')}`,
					{ failedAreas: cascade.failedAreas }
				);
			}
			return { ok: true, destroyed: cascade.destroyed };
		}
	);
