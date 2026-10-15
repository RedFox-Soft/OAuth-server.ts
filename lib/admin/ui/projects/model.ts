import type { Project, UserBucket } from '../../../adapters/types.js';

/*
 * The buckets a project can actually be pointed at.
 *
 * `GET /admin/api/buckets` is not that list and was used as one. It hands a super administrator every
 * bucket on the instance, and hands anyone else the buckets already backing their projects on top of
 * the ones their group owns — neither of which the assignment route accepts unless the bucket shares
 * the project's owning group. Offering the rest puts a choice on the screen that answers 409, which is
 * how the default bucket came to be listed and unusable.
 *
 * The default bucket is therefore never here: it belongs to no group, and the route accepts it from a
 * super administrator alone (specs/098), so a screen offering it adds it for them explicitly.
 */
export function assignableBuckets(
	buckets: readonly UserBucket[],
	project: Pick<Project, 'ownerGroupId'>
): UserBucket[] {
	// A bucket scheduled for deletion refuses new projects (specs/090), so it is not offered either.
	return buckets.filter(
		(bucket) => bucket.ownerGroupId === project.ownerGroupId && !bucket.deletion
	);
}
