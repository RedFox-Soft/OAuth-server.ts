import { getUserStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { mailDeliveryConfigured } from '../../mail/mailer.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';

/*
 * The administrators' bucket is configured through the same settings as every bucket; what differs is that
 * a careless setting here shuts the console, and with it the only surface that could undo the setting. Each
 * such setting carries its own guard instead of the blanket refusal this bucket used to get.
 *
 * Turning password sign-in off needs nothing here: `assertSomeWayToSignIn` already refuses it, because this
 * bucket holds no provider and federation stays closed to it.
 *
 * Requiring verification is the one that needed a guard of its own. It refuses every unverified
 * administrator at the door, so it may be turned on only when the message can actually be sent, and only by
 * someone the requirement cannot lock out: the person changing it must already have proven their own
 * address, so the requirement can never refuse the one administrator who set it.
 */
export async function assertAdminBucketChange(
	ctx: AdminContext,
	patch: { emailVerificationRequired?: boolean }
): Promise<void> {
	if (patch.emailVerificationRequired !== true) return;
	if (!(await mailDeliveryConfigured())) {
		throw new AdminError(
			409,
			'administrators could not receive the verification message: configure mail delivery first'
		);
	}
	const acting = await getUserStore(ADMIN_BUCKET_ID).find(ctx.userId);
	if (!acting?.verified) {
		throw new AdminError(
			409,
			'verify your own address before requiring verification of administrators'
		);
	}
}

/*
 * Said on every write that leaves the bucket in this state rather than refused: an open console with no
 * proof of address is a legitimate choice for an instance behind its own network, but it is one an operator
 * should make knowingly, and an agent reading the response gets the same sentence the console shows.
 */
export function adminBucketAdvisory(
	bucket: Pick<UserBucket, 'registrationOpen' | 'emailVerificationRequired'>
): string | undefined {
	if (!bucket.registrationOpen || bucket.emailVerificationRequired) {
		return undefined;
	}
	return 'anyone can register an administrator account, and without email verification any address can be claimed';
}
