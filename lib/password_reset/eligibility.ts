import type { UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';

/*
 * Whether a bucket offers self-service password reset at all — a property of the bucket, never of an
 * address, so answering it on the sign-in page reveals nothing about who has an account.
 *
 * One predicate for the three places that ask: the request, the link, and the sign-in page deciding whether
 * to show "Forgot password". They used to carry the conditions separately, and a page that offers a door its
 * own bucket keeps shut is the defect this replaced.
 *
 * - The reserved admin bucket is refused because an end-user reset records no actor, and an operator's
 *   credentials must not be changeable through a path with nothing to attribute; console passwords stay
 *   inside the admin plane's audited route.
 * - A bucket with no password door has no password to reset, and a reset is exactly how a password would
 *   reach an account meant to sign in only through its identity provider.
 * - A bucket that cannot be found offers nothing.
 */
export function selfServiceResetAllowed(
	bucketId: string,
	bucket: Pick<UserBucket, 'passwordLogin'> | null
): boolean {
	if (bucketId === ADMIN_BUCKET_ID) return false;
	return bucket !== null && bucket.passwordLogin;
}
