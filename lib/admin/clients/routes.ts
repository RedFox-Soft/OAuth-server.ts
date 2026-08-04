import { Elysia } from 'elysia';
import { getProjectStore } from '../../adapters/index.js';
import { InvalidClientMetadata } from '../../helpers/errors.js';
import {
	assertAuth,
	assertProjectAccess,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_CLIENT_ID } from '../consts.js';
import { CreateClientBody, UpdateClientBody } from './schema.js';
import {
	createClient,
	getClientView,
	updateClient,
	rotateSecret,
	deleteClientRecord
} from './service.js';
import { recordAdminAudit } from '../audit/record.js';
import { cascadeForClient } from '../../helpers/cascade.js';
import nanoid from '../../helpers/nanoid.js';

// Load a REGULAR project the caller may access, or throw. Client management never
// applies to the reserved admin project.
async function loadManageableProject(admin: AdminContext, id: string) {
	const project = await getProjectStore().find(id);
	if (!project) throw new AdminError(404, 'project not found');
	if (project.type === 'admin')
		throw new AdminError(403, 'cannot manage admin project clients');
	assertProjectAccess(admin, project);
	return project;
}

// Ownership scoping: the client id must belong to this project.
function assertOwnsClient(project: { clientIds: string[] }, clientId: string) {
	if (clientId === ADMIN_CLIENT_ID)
		throw new AdminError(403, 'cannot manage the reserved admin client');
	if (!project.clientIds.includes(clientId))
		throw new AdminError(404, 'client not found in this project');
}

export const clientRoutes = new Elysia({ name: 'admin-clients' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
		// Client metadata validation failure → 422.
		if (error instanceof InvalidClientMetadata) {
			set.status = 422;
			return { error: 'invalid_client_metadata', message: error.message };
		}
	})
	.get('/admin/api/projects/:id/clients', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const project = await loadManageableProject(ctx, params.id);
		const views = [];
		for (const clientId of project.clientIds) {
			const view = await getClientView(clientId);
			if (view) views.push(view);
		}
		return views;
	})
	.post(
		'/admin/api/projects/:id/clients',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			// Allocated here so the entry names the client that is about to exist. One entry for the
			// request, even though it also attaches the client to its project.
			const clientId = nanoid();
			await recordAdminAudit(ctx, 'client.create', clientId);
			const { view, secret } = await createClient({ ...body, clientId });
			await getProjectStore().update(params.id, {
				clientIds: [...project.clientIds, view.clientId]
			});
			set.status = 201;
			return { ...view, secret };
		},
		{ body: CreateClientBody }
	)
	.get(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			const view = await getClientView(params.clientId);
			if (!view) throw new AdminError(404, 'client not found');
			return view;
		}
	)
	.patch(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			await recordAdminAudit(ctx, 'client.update', params.clientId, {
				attributes: Object.keys(body)
			});
			return updateClient(params.clientId, body);
		},
		{ body: UpdateClientBody }
	)
	.post(
		'/admin/api/projects/:id/clients/:clientId/secret',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			// The rotation is the recorded fact; the secret itself never enters the trail.
			await recordAdminAudit(ctx, 'client.secret.rotate', params.clientId);
			const secret = await rotateSecret(params.clientId);
			return { clientId: params.clientId, secret };
		}
	)
	.delete(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			await recordAdminAudit(ctx, 'client.delete', params.clientId);
			await deleteClientRecord(params.clientId);
			await getProjectStore().update(params.id, {
				clientIds: project.clientIds.filter((c) => c !== params.clientId)
			});
			/*
			 * Audit, then destroy the principal, then cascade — and "destroy the principal" is both the
			 * record delete and the unlink above, so the sweep runs after both rather than between them:
			 * the client is not gone from the admin plane until neither half of it remains.
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
