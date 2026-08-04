import { Elysia } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadBucketForUsers } from '../buckets/access.js';
import {
	CreateEndUserBody,
	UpdateEndUserBody,
	ResetPasswordBody
} from './schema.js';
import { recordAdminAudit } from '../audit/record.js';
import { cascadeForAccount } from '../../helpers/cascade.js';
import nanoid from '../../helpers/nanoid.js';

function assertRolesSubset(
	roles: string[] | undefined,
	bucket: UserBucket
): void {
	if (!roles) return;
	const bad = roles.filter((r) => !bucket.roles.includes(r));
	if (bad.length) {
		throw new AdminError(
			422,
			`roles not declared on bucket: ${bad.join(', ')}`
		);
	}
}

const strip = (u: { password?: string }) => {
	const { password: _password, ...safe } = u;
	return safe;
};

export const endUserRoutes = new Elysia({ name: 'admin-users-end' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/buckets/:id/users', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		await loadBucketForUsers(ctx, params.id);
		const users = await getUserStore(params.id).list();
		return users.map(strip);
	})
	.post(
		'/admin/api/buckets/:id/users',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			assertRolesSubset(body.roles, bucket);
			const store = getUserStore(params.id);
			if (await store.findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists');
			}
			const hash = await Bun.password.hash(body.password);
			// Allocated here so the entry names the account that is about to exist. The bucket travels as
			// the scope: these users live in per-bucket storage, so an id alone resolves to nobody.
			const userId = nanoid();
			await recordAdminAudit(ctx, 'enduser.create', userId, {
				targetScope: params.id
			});
			const user = await store.create(
				body.email,
				hash,
				body.roles ?? [],
				true,
				userId
			);
			set.status = 201;
			return strip(user);
		},
		{ body: CreateEndUserBody }
	)
	.patch(
		'/admin/api/buckets/:id/users/:uid',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			assertRolesSubset(body.roles, bucket);
			await recordAdminAudit(ctx, 'enduser.update', params.uid, {
				targetScope: params.id,
				attributes: Object.keys(body)
			});
			const updated = await getUserStore(params.id).update(params.uid, body);
			if (!updated) throw new AdminError(404, 'user not found');
			return strip(updated);
		},
		{ body: UpdateEndUserBody }
	)
	.post(
		'/admin/api/buckets/:id/users/:uid/password',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForUsers(ctx, params.id);
			const hash = await Bun.password.hash(body.password);
			// The reset is the recorded fact. No attribute names either: naming the field would say
			// nothing the action does not, and the value must never be near the trail.
			await recordAdminAudit(ctx, 'enduser.password.reset', params.uid, {
				targetScope: params.id
			});
			const updated = await getUserStore(params.id).update(params.uid, {
				password: hash
			});
			if (!updated) throw new AdminError(404, 'user not found');
			return { ok: true };
		},
		{ body: ResetPasswordBody }
	)
	.delete('/admin/api/buckets/:id/users/:uid', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		await loadBucketForUsers(ctx, params.id);
		const store = getUserStore(params.id);
		const user = await store.find(params.uid);
		if (!user) {
			throw new AdminError(404, 'user not found');
		}
		/*
		 * The email is read here, before the row goes, because the email-scoped areas (VerificationResend,
		 * PasswordResetThrottle) are addressed by `${bucketId}:${email}` and nothing else records it.
		 * Destroy first and those records are unreachable — skipped in silence, with no error anywhere to
		 * notice.
		 */
		const emailScopedId = user.email ? `${params.id}:${user.email}` : null;
		await recordAdminAudit(ctx, 'enduser.delete', params.uid, {
			targetScope: params.id
		});
		await store.destroy(params.uid);
		/* Audit, then destroy the principal, then cascade; a failed sweep is reported, never rolled back. */
		const cascade = await cascadeForAccount(params.uid, emailScopedId);
		if (cascade.failedAreas.length > 0) {
			throw new AdminError(
				500,
				`user deleted, but their records survive in: ${cascade.failedAreas.join(', ')}`,
				{ failedAreas: cascade.failedAreas }
			);
		}
		return { ok: true, destroyed: cascade.destroyed };
	});
