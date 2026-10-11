import { getBucketStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { AdminError, projectReach, type AdminContext } from '../auth/rbac.js';
import { bucketCan, holdsBucket, NO_PROJECT_REACH } from '../auth/can.js';

/*
 * What a missing bucket answers.
 *
 * A caller without instance-wide authority gets the same refusal for a bucket that does not exist as
 * for one owned by another group, so walking ids reveals nothing about which are real. A super
 * administrator still gets 404, because there is no tenant they could be probing and a plain "not
 * found" is what actually helps them.
 */
function notFoundStatus(admin: AdminContext): number {
	return admin.superAdmin ? 404 : 403;
}

/*
 * Whether the caller holds `right` on this bucket — decided by the predicates the bucket's stated rights
 * come from (`can.ts`), so a loader refuses exactly when the console was told the right is false.
 *
 * The project reach is read only when it could change the answer: reading and managing users are widened
 * by a project only for a caller who does not hold the bucket, and editing never is.
 */
async function holds(
	admin: AdminContext,
	bucket: UserBucket,
	right: 'read' | 'manageUsers' | 'editSettings' | 'edit'
): Promise<boolean> {
	const widenedByProjects = right === 'read' || right === 'manageUsers';
	const access =
		widenedByProjects && !holdsBucket(admin, bucket)
			? await projectReach(admin)
			: NO_PROJECT_REACH;
	return bucketCan(admin, bucket, access)[right];
}

/*
 * Every bucket operation except its settings and its identity providers stays closed to the administrators'
 * bucket: its accounts are administrators (managed on their own routes, with personal groups and the
 * instance privilege attached), and provisioning, bucket groups and the users' identities would each reach
 * console access through a door nobody designed for it. The providers have their own loader below, with the
 * guards that door needs (specs/080). Kept inside the two shared loaders deliberately — they
 * guard some forty routes, and opening them would admit all of those at once with nothing behind them.
 */
function assertNotReserved(id: string): void {
	if (id === ADMIN_BUCKET_ID) {
		throw new AdminError(
			403,
			"this operation is not available for the administrators' bucket"
		);
	}
}

// Load a bucket for reading detail / managing its users (broad access).
export async function loadBucketForUsers(
	admin: AdminContext,
	id: string
): Promise<UserBucket> {
	assertNotReserved(id);
	const bucket = await getBucketStore().find(id);
	if (!bucket)
		throw new AdminError(notFoundStatus(admin), 'no access to this bucket');
	if (!(await holds(admin, bucket, 'manageUsers'))) {
		throw new AdminError(403, 'no access to this bucket');
	}
	return bucket;
}

/*
 * Load a bucket for its settings: the detail read and the settings change. The one loader that admits the
 * administrators' bucket, and only for a super administrator.
 *
 * Refused explicitly here rather than left to ownership: the bucket belongs to the System group, which has
 * no members, so `assertBucketAccess` would refuse anyone else today — but that is an invariant of the
 * group, stated nowhere it is enforced, and this is where the console's own bucket is guarded.
 */
export async function loadBucketForSettings(
	admin: AdminContext,
	id: string,
	mode: 'read' | 'edit'
): Promise<UserBucket> {
	if (id === ADMIN_BUCKET_ID && !admin.superAdmin) {
		throw new AdminError(notFoundStatus(admin), 'no access to this bucket');
	}
	const bucket = await getBucketStore().find(id);
	if (!bucket)
		throw new AdminError(notFoundStatus(admin), 'no access to this bucket');
	if (
		!(await holds(admin, bucket, mode === 'read' ? 'read' : 'editSettings'))
	) {
		throw new AdminError(403, 'no access to this bucket');
	}
	return bucket;
}

/*
 * Load a bucket for its identity providers (specs/080). The administrators' bucket is admitted for a super
 * administrator only — whoever configures its providers decides who can sign in to the console — exactly as
 * its settings are. On every other bucket `read` and `editSettings` answer as `manageUsers` and `edit` do, so
 * ordinary buckets' providers keep the rights they had.
 */
export function loadBucketForProviders(
	admin: AdminContext,
	id: string,
	mode: 'read' | 'edit'
): Promise<UserBucket> {
	return loadBucketForSettings(admin, id, mode);
}

// Load a bucket for mutating the bucket entity itself (strict access).
export async function loadBucketForEdit(
	admin: AdminContext,
	id: string
): Promise<UserBucket> {
	assertNotReserved(id);
	const bucket = await getBucketStore().find(id);
	if (!bucket)
		throw new AdminError(notFoundStatus(admin), 'no access to this bucket');
	if (!(await holds(admin, bucket, 'edit'))) {
		throw new AdminError(403, 'no access to this bucket');
	}
	return bucket;
}
