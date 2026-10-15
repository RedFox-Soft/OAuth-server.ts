import { getBucketStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import type { AdminContext } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';

/*
 * The buckets an administrator's bucket list shows them — and therefore the buckets every cross-bucket
 * count is taken over (specs/088 R8), so a count and the list it summarises cannot disagree.
 *
 * Listing has to agree with access: the `read` right is membership of the bucket's group (specs/099), so
 * the list is the active group's buckets. A super administrator configures the administrators' bucket like
 * any other, so it is listed for them; for anyone else it stays out of the list, as it is out of reach.
 */
export async function visibleBuckets(ctx: AdminContext): Promise<UserBucket[]> {
	const store = getBucketStore();
	const all = ctx.superAdmin
		? await store.list()
		: await store.listByGroup(ctx.activeGroupId);
	return all.filter((b) => ctx.superAdmin || b._id !== ADMIN_BUCKET_ID);
}
