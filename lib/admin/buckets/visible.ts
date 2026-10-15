import { getBucketStore, getProjectStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { bucketReachedThrough, type AdminContext } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';

/*
 * The buckets an administrator's bucket list shows them — and therefore the buckets every cross-bucket
 * count is taken over (specs/088 R8), so a count and the list it summarises cannot disagree.
 *
 * Listing has to agree with access, or the console shows an administrator fewer buckets than it will let
 * them open. The `read` right admits a bucket backing a project the caller's group owns, so the list admits
 * it too. A super administrator configures the administrators' bucket like any other, so it is listed for
 * them; for anyone else it stays out of the list, as it is out of reach.
 */
export async function visibleBuckets(ctx: AdminContext): Promise<UserBucket[]> {
	const store = getBucketStore();
	let all: UserBucket[];
	if (ctx.superAdmin) {
		all = await store.list();
	} else {
		const owned = await store.listByGroup(ctx.activeGroupId);
		const projects = await getProjectStore().listByGroup(ctx.activeGroupId);
		const backing = projects
			.map(bucketReachedThrough)
			.filter((id): id is string => id !== undefined);
		const missing = backing.filter((id) => !owned.some((b) => b._id === id));
		const extra = (
			await Promise.all(missing.map((id) => store.find(id)))
		).filter((b): b is UserBucket => b !== null);
		all = [...owned, ...extra];
	}
	return all.filter((b) => ctx.superAdmin || b._id !== ADMIN_BUCKET_ID);
}
