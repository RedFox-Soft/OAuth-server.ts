import { Elysia } from 'elysia';
import { getProjectStore } from '../../adapters/index.js';
import { InvalidClientMetadata } from '../../helpers/errors.js';
import {
	assertAuth,
	assertProjectAccess,
	AdminError,
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
			return { error: 'admin_error', message: error.message };
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
			const { view, secret } = await createClient(body);
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
			await deleteClientRecord(params.clientId);
			await getProjectStore().update(params.id, {
				clientIds: project.clientIds.filter((c) => c !== params.clientId)
			});
			return { ok: true };
		}
	);
