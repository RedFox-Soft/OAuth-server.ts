import { getBucketStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	AdminError,
	assertBucketAccess,
	assertBucketUserAccess,
	type AdminContext
} from '../auth/rbac.js';

function assertNotReserved(id: string): void {
	if (id === ADMIN_BUCKET_ID) {
		throw new AdminError(403, 'the admin bucket is managed via /admin/api/admins');
	}
}

// Load a bucket for reading detail / managing its users (broad access).
export async function loadBucketForUsers(
	admin: AdminContext,
	id: string
): Promise<UserBucket> {
	assertNotReserved(id);
	const bucket = await getBucketStore().find(id);
	if (!bucket) throw new AdminError(404, 'bucket not found');
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
	if (!bucket) throw new AdminError(404, 'bucket not found');
	assertBucketAccess(admin, bucket);
	return bucket;
}
