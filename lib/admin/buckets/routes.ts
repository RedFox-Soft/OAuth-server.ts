import { Elysia } from 'elysia';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from '../../adapters/index.js';
import {
	assertAuth,
	assertActiveGroup,
	assertBucketAccess,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import type { UserBucket } from '../../adapters/types.js';
import { presentAll } from '../federation/service.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import { loadBucketForUsers, loadBucketForEdit } from './access.js';
import {
	assertSomeWayToSignIn,
	prospectiveBucket
} from '../federation/validate.js';
import { CreateBucketBody, UpdateBucketBody } from './schema.js';

/*
 * A bucket as a reader may see it: identical except that every configured provider's `clientSecret` is
 * masked.
 *
 * `lib/admin/federation/service.ts` states the rule these routes were breaking — the secret is
 * write-only, masked "on every read, for every role including super-admin". It held on the federation
 * routes and not here, because a bucket document *contains* its providers and these handlers returned it
 * whole. So `GET /admin/api/buckets` handed every provider secret to any authenticated administrator, and
 * `GET /admin/api/buckets/:id` handed a bucket's secrets to anyone with the broader
 * `loadBucketForUsers` access — a project manager, not only the bucket's own.
 *
 * Found by the MCP surface's secrecy sweep (test/mcp/secrecy.spec.ts), which is why that sweep iterates
 * every published read rather than the ones somebody thought to check.
 */
function presentBucket<T extends Pick<UserBucket, 'federation'>>(bucket: T): T {
	if (!bucket.federation?.length) return bucket;
	return { ...bucket, federation: presentAll(bucket) as T['federation'] };
}

/*
 * A second factor on a bucket that accepts no passwords is inert, not wrong: the requirement governs
 * the password door, and there is no password door. Recording the intended posture before opening one
 * is a reasonable order to do things in, so this says so rather than refusing — a 422 here would make
 * an operator turn password login on, set the flag, and turn it back off to express what they meant.
 *
 * Only on the write paths. A read that carried it would repeat the same sentence on every poll of a
 * federation-only bucket, which trains an operator to ignore it.
 */
function withInertTotpAdvisory<
	T extends Pick<UserBucket, 'totpRequired' | 'passwordLogin'>
>(bucket: T): T | (T & { advisory: string }) {
	if (!bucket.totpRequired || bucket.passwordLogin !== false) return bucket;
	return {
		...bucket,
		advisory:
			'totpRequired has no effect while passwordLogin is off — it governs password sign-in, and federated sign-in is never gated by it'
	};
}

export const bucketRoutes = new Elysia({ name: 'admin-buckets' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/buckets', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getBucketStore();
		/*
		 * Listing has to agree with access, or the console shows an administrator fewer buckets than it
		 * will let them open. `assertBucketUserAccess` admits a bucket backing a project the caller's
		 * group owns, so the list has to admit it too — it did not before this feature, and a bucket you
		 * could administer but never see was the result.
		 */
		let all;
		if (ctx.roles.includes('super_admin')) {
			all = await store.list();
		} else {
			const owned = await store.listByGroup(ctx.activeGroupId);
			const projects = await getProjectStore().listByGroup(ctx.activeGroupId);
			const backing = projects
				.map((p) => p.bucketId)
				.filter((id): id is string => id !== null);
			const missing = backing.filter((id) => !owned.some((b) => b._id === id));
			const extra = (
				await Promise.all(missing.map((id) => store.find(id)))
			).filter((b): b is NonNullable<typeof b> => b !== null);
			all = [...owned, ...extra];
		}
		return all.filter((b) => b._id !== ADMIN_BUCKET_ID).map(presentBucket);
	})
	.post(
		'/admin/api/buckets',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			// No role gate: the authority is membership of the group the bucket will belong to.
			const ownerGroupId = assertActiveGroup(ctx);
			/*
			 * A new bucket cannot be created unreachable. Providers are added through their own routes, so at
			 * creation there are none — which makes `passwordLogin: false` here always a lockout.
			 */
			assertSomeWayToSignIn({
				passwordLogin: body.passwordLogin !== false,
				federation: []
			});
			// The id is allocated here, not by the store, so the audit entry can name the bucket that is
			// about to exist — audit-first has nothing to point at otherwise.
			const bucketId = nanoid();
			await recordAdminAudit(ctx, 'bucket.create', bucketId, { ownerGroupId });
			const bucket = await getBucketStore().create({
				_id: bucketId,
				name: body.name,
				roles: body.roles ?? [],
				ownerGroupId,
				passwordLogin: body.passwordLogin,
				registrationOpen: body.registrationOpen,
				emailVerificationRequired: body.emailVerificationRequired,
				verificationMethod: body.verificationMethod,
				totpRequired: body.totpRequired
			});
			set.status = 201;
			// No advisory is reachable here: the guard above proves a new bucket accepts passwords, so
			// the requirement can never be inert at creation.
			return presentBucket(bucket);
		},
		{ body: CreateBucketBody }
	)
	.get('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		return presentBucket(await loadBucketForUsers(ctx, params.id));
	})
	.patch(
		'/admin/api/buckets/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			/*
			 * Checked before the audit entry and the write: an entry describing a change a 409 refused would
			 * state that an operator closed a bucket's password door when they did not. The provider routes
			 * enforce the same rule from the other direction, through the same function.
			 */
			assertSomeWayToSignIn(prospectiveBucket(bucket, body));
			/*
			 * Recorded whatever the request changed. This used to fire only for a registration or
			 * verification field, so renaming a bucket or reassigning its managers left no trace at all
			 * — while still being an exercised privilege over who can administer a bucket's users.
			 */
			await recordAdminAudit(ctx, 'bucket.update', params.id, {
				attributes: Object.keys(body),
				ownerGroupId: bucket.ownerGroupId
			});
			const updated = await getBucketStore().update(params.id, body);
			if (!updated) throw new AdminError(404, 'bucket not found');
			return withInertTotpAdvisory(presentBucket(updated));
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
		/*
		 * Guarded rather than cascaded, like a project: its users are accounts the operator can see and
		 * name. `list()` does not filter, which is what makes a deactivated account count — deactivation is
		 * a sign-in decision, not absence, and the account is still there to be destroyed. Only the count
		 * is reported: a bucket can hold thousands of accounts and their identifiers are not the caller's
		 * business.
		 */
		const store = getUserStore(params.id);
		const held = (await store.list()).length;
		if (held > 0) {
			throw new AdminError(409, 'bucket still holds end-users', {
				blockers: [{ kind: 'enduser', count: held }]
			});
		}
		// After the guards, before the deletion: an entry for a request the 409 refused would describe
		// a deletion that was never even attempted.
		await recordAdminAudit(ctx, 'bucket.delete', params.id);
		await getBucketStore().destroy(params.id);
		/* The half that was missing: without this a deleted bucket left its `user_<bucket>` area behind
		 * for good, indexes and all. Safe here and only here, because the guard above proved it empty. */
		await store.destroyArea();
		return { ok: true };
	});
