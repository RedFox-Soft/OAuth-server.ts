import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import type { UserBucket } from '../adapters/types.js';

/*
 * Whether a project's accounts are emailed about a sign-in from a new network or browser (specs/138 research R3).
 * Absent means off for a project of people, whose operator decides what their people receive, and on for the
 * administrators' project, whose accounts are the most valuable on the server; a super administrator may still turn it
 * off. Held as an absent field rather than a stored default, so no project record needs rewriting.
 */
export function alertsOn(
	bucket: Pick<UserBucket, '_id' | 'newSignInAlerts'>
): boolean {
	return bucket.newSignInAlerts ?? bucket._id === ADMIN_BUCKET_ID;
}
