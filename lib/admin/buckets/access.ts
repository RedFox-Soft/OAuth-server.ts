import { getBucketStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	AdminError,
	assertBucketAccess,
	assertBucketUserAccess,
	type AdminContext
} from '../auth/rbac.js';

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
 * Every bucket operation except reading and changing its settings stays closed to the administrators'
 * bucket: its accounts are administrators (managed on their own routes, with personal groups and the
 * instance privilege attached), and federation, provisioning and bucket groups would each reach console
 * access through a door nobody designed for it. Kept inside the two shared loaders deliberately — they
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
	await assertBucketUserAccess(admin, bucket);
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
	if (mode === 'read') await assertBucketUserAccess(admin, bucket);
	else assertBucketAccess(admin, bucket);
	return bucket;
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
	assertBucketAccess(admin, bucket);
	return bucket;
}
