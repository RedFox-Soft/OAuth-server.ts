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

async function loadProject(id: string) {
	const project = await getProjectStore().find(id);
	if (!project) throw new AdminError(404, 'project not found');
	return project;
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
			const project = await store.create({
				name: body.name,
				slug: body.slug,
				type: 'regular',
				managedBy: body.managedBy ?? []
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
			return getProjectStore().update(params.id, body);
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
