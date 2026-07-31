import { Elysia } from 'elysia';
import { getProjectStore, getBucketStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	assertProjectAccess,
	assertBucketAccess,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody
} from './schema.js';
import {
	InvalidOriginError,
	normalizeOrigins
} from '../../helpers/cors_origin.js';

async function loadProject(id: string) {
	const project = await getProjectStore().find(id);
	if (!project) throw new AdminError(404, 'project not found');
	return project;
}

/*
 * Normalizes a submitted origin list, or refuses the whole request. All-or-nothing on purpose: half a
 * list is a configuration an operator did not ask for, and the browser-facing consequence of a silently
 * dropped entry is an app that cannot reach the server.
 */
function validateCorsOrigins(origins: string[] | undefined) {
	if (origins === undefined) {
		return undefined;
	}
	try {
		return normalizeOrigins(origins);
	} catch (err) {
		if (err instanceof InvalidOriginError) {
			throw new AdminError(400, err.message);
		}
		throw err;
	}
}

export const projectRoutes = new Elysia({ name: 'admin-projects' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.get('/admin/api/projects', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getProjectStore();
		const all = ctx.roles.includes('super_admin')
			? (await store.list()).filter((p) => p.type === 'regular')
			: (await store.listByManager(ctx.userId)).filter(
					(p) => p.type === 'regular'
				);
		return all;
	})
	.post(
		'/admin/api/projects',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			const store = getProjectStore();
			if (await store.findBySlug(body.slug)) {
				throw new AdminError(409, 'slug already exists');
			}
			// Every accepted key must be forwarded explicitly: the store takes more than this handler
			// passes, so a schema addition alone would accept a value and silently discard it.
			const project = await store.create({
				name: body.name,
				slug: body.slug,
				type: 'regular',
				managedBy: body.managedBy ?? [],
				corsOrigins: validateCorsOrigins(body.corsOrigins) ?? []
			});
			set.status = 201;
			return project;
		},
		{ body: CreateProjectBody }
	)
	.get('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const project = await loadProject(params.id);
		assertProjectAccess(ctx, project);
		return project;
	})
	.patch(
		'/admin/api/projects/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(params.id);
			if (project.type === 'admin')
				throw new AdminError(403, 'cannot modify admin project');
			assertProjectAccess(ctx, project);
			if (body.managedBy !== undefined) assertRole(ctx, 'super_admin');
			const corsOrigins = validateCorsOrigins(body.corsOrigins);
			return getProjectStore().update(params.id, {
				...body,
				...(corsOrigins === undefined ? {} : { corsOrigins })
			});
		},
		{ body: UpdateProjectBody }
	)
	.delete('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		const project = await loadProject(params.id);
		if (project.type === 'admin')
			throw new AdminError(403, 'cannot delete admin project');
		await getProjectStore().destroy(params.id);
		return { ok: true };
	})
	.put(
		'/admin/api/projects/:id/bucket',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(params.id);
			assertProjectAccess(ctx, project);
			const bucket = await getBucketStore().find(body.bucketId);
			if (!bucket) throw new AdminError(404, 'bucket not found');
			assertBucketAccess(ctx, bucket);
			return getProjectStore().update(params.id, { bucketId: body.bucketId });
		},
		{ body: SetBucketBody }
	);
