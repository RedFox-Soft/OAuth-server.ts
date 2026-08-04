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
import { ADMIN_BUCKET_ID } from '../consts.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import { loadBucketForUsers, loadBucketForEdit } from './access.js';
import { CreateBucketBody, UpdateBucketBody } from './schema.js';

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
		const all = ctx.roles.includes('super_admin')
			? await store.list()
			: await store.listByManager(ctx.userId);
		return all.filter((b) => b._id !== ADMIN_BUCKET_ID);
	})
	.post(
		'/admin/api/buckets',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			// The id is allocated here, not by the store, so the audit entry can name the bucket that is
			// about to exist — audit-first has nothing to point at otherwise.
			const bucketId = nanoid();
			await recordAdminAudit(ctx, 'bucket.create', bucketId);
			const bucket = await getBucketStore().create({
				_id: bucketId,
				name: body.name,
				roles: body.roles ?? [],
				managedBy: body.managedBy ?? [ctx.userId],
				registrationOpen: body.registrationOpen,
				emailVerificationRequired: body.emailVerificationRequired,
				verificationMethod: body.verificationMethod
			});
			set.status = 201;
			return bucket;
		},
		{ body: CreateBucketBody }
	)
	.get('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		return loadBucketForUsers(ctx, params.id);
	})
	.patch(
		'/admin/api/buckets/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForEdit(ctx, params.id);
			if (body.managedBy !== undefined) {
				assertRole(ctx, 'super_admin');
			}
			/*
			 * Recorded whatever the request changed. This used to fire only for a registration or
			 * verification field, so renaming a bucket or reassigning its managers left no trace at all
			 * — while still being an exercised privilege over who can administer a bucket's users.
			 */
			await recordAdminAudit(ctx, 'bucket.update', params.id, {
				attributes: Object.keys(body)
			});
			const updated = await getBucketStore().update(params.id, body);
			if (!updated) throw new AdminError(404, 'bucket not found');
			return updated;
		},
		{ body: UpdateBucketBody }
	)
	.delete('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const bucket = await getBucketStore().find(params.id);
		if (!bucket) throw new AdminError(404, 'bucket not found');
		assertBucketAccess(ctx, bucket);
		if ((await getProjectStore().countByBucket(params.id)) > 0) {
			throw new AdminError(409, 'bucket is assigned to one or more projects');
		}
		// After the guards, before the deletion: an entry for a request the 409 refused would describe
		// a deletion that was never even attempted.
		await recordAdminAudit(ctx, 'bucket.delete', params.id);
		await getBucketStore().destroy(params.id);
		return { ok: true };
	});
