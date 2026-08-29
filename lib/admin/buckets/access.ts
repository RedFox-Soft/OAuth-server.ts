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
	return admin.roles.includes('super_admin') ? 404 : 403;
}

function assertNotReserved(id: string): void {
	if (id === ADMIN_BUCKET_ID) {
		throw new AdminError(
			403,
			'the admin bucket is managed via /admin/api/admins'
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
