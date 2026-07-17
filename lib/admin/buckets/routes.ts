import { Elysia } from 'elysia';
import { getBucketStore, getProjectStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	assertBucketAccess,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { CreateBucketBody } from './schema.js';

export const bucketRoutes = new Elysia({ name: 'admin-buckets' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.get('/admin/api/buckets', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getBucketStore();
		return ctx.roles.includes('super_admin')
			? store.list()
			: store.listByManager(ctx.userId);
	})
	.post(
		'/admin/api/buckets',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			const bucket = await getBucketStore().create({
				name: body.name,
				roles: body.roles ?? [],
				managedBy: body.managedBy ?? [ctx.userId]
			});
			set.status = 201;
			return bucket;
		},
		{ body: CreateBucketBody }
	)
	.delete('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const bucket = await getBucketStore().find(params.id);
		if (!bucket) throw new AdminError(404, 'bucket not found');
		assertBucketAccess(ctx, bucket);
		if ((await getProjectStore().countByBucket(params.id)) > 0) {
			throw new AdminError(409, 'bucket is assigned to one or more projects');
		}
		await getBucketStore().destroy(params.id);
		return { ok: true };
	});
