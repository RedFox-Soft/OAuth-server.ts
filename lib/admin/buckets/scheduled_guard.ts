import { Elysia } from 'elysia';

import { getBucketStore } from '../../adapters/index.js';
import { AdminError, projectReach, resolveAdmin } from '../auth/rbac.js';
import { bucketCan, holdsBucket, NO_PROJECT_REACH } from '../auth/can.js';

const BUCKET = '/admin/api/buckets/:id';

/* The two writes that exist for a scheduled bucket: taking it back, and ending it now. */
const SCHEDULED_ONLY = new Set([`${BUCKET}/restore`, `${BUCKET}/purge`]);

/*
 * Whether a mounted route changes a bucket or something it holds — every route beneath the bucket's own
 * path that is not a read. Keyed on the route pattern rather than listed, so a route added under the prefix
 * later is guarded without anyone remembering to (test/admin/bucket_scheduled_writes.spec.ts enumerates the
 * mounted routes to prove it).
 */
export function writesIntoBucket(method: string, route: string): boolean {
	if (method === 'GET' || method === 'HEAD') return false;
	if (route !== BUCKET && !route.startsWith(`${BUCKET}/`)) return false;
	return !SCHEDULED_ONLY.has(route);
}

/* The refusal every change to a scheduled bucket gets, with the date it will be destroyed. */
export function scheduledForDeletion(purgeAt: Date): AdminError {
	return new AdminError(
		409,
		`This bucket is scheduled for deletion on ${purgeAt.toISOString().slice(0, 10)}. Restore it first.`
	);
}

/*
 * Every administrative change to a bucket scheduled for deletion is refused until it is restored (specs/090
 * FR-010) — from the console and, because the agent surface dispatches into these same routes, from an agent.
 *
 * One hook rather than a check in each loader: the loaders serve reads and writes alike, so a check there
 * would need an opt-out at every read, and one forgotten opt-out is a page that stops loading.
 *
 * It answers only a caller who may read the bucket. Anyone else passes through to the handler, which refuses
 * them exactly as it did before — a 409 here would tell a stranger that a bucket exists and is scheduled.
 *
 * `scoped`, so the hook lands on the admin route set that mounts it and reaches the route groups mounted
 * after it there.
 */
export const scheduledBucketGuard = new Elysia({
	name: 'admin-scheduled-bucket-guard'
})
	.use(resolveAdmin)
	.onBeforeHandle(
		{ as: 'scoped' },
		async ({ admin, request, route, params }) => {
			if (!admin || !writesIntoBucket(request.method, route)) return;
			const id: unknown = Reflect.get(params, 'id');
			if (typeof id !== 'string') return;
			const bucket = await getBucketStore().find(id);
			if (!bucket?.deletion) return;
			const access = holdsBucket(admin, bucket)
				? NO_PROJECT_REACH
				: await projectReach(admin);
			if (!bucketCan(admin, bucket, access).read) return;
			throw scheduledForDeletion(bucket.deletion.purgeAt);
		}
	);
