import { getPasskeyStore } from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import epochTime from '../helpers/epoch_time.js';
import { mailDeliveryConfigured } from '../mail/mailer.js';
import { passkeysAccepted } from './accepted.js';
import { OFFER_PAUSE_SECONDS, PASSKEYS_PER_PERSON } from './consts.js';

/*
 * The prompt-time half of the passkey offer (specs/141 research R3, R4), apart from lib/passkeys/offer.ts so the
 * interaction policy, which every authorization request builds, does not import the ceremonies, the mail and the
 * end-user service behind them.
 */

export type OfferKind = 'full' | 'conditional';

/*
 * Whether the person may be shown the offer now (research R4), beyond what the sign-in itself decided: the project
 * accepts passkeys and offers them, mail works (every passkey is mailed about), the address is confirmed, the person
 * holds fewer than twenty, and they neither declined for good, nor are held back by "This wasn't me", nor saw the offer
 * in the last thirty days.
 */
export async function offerable(
	bucket: UserBucket,
	user: User,
	{
		now = epochTime(),
		thisShowing = false
	}: {
		now?: number;
		/* The showing being judged is the one already counted (a reload): its own pause does not hide it. */
		thisShowing?: boolean;
	} = {}
): Promise<boolean> {
	if (!passkeysAccepted(bucket) || bucket.passkeyOffer === false) return false;
	if (!user.verified) return false;
	const state = user.passkeyOffer;
	if (state?.never === true || state?.held === true) return false;
	if (
		!thisShowing &&
		state?.lastShownAt !== undefined &&
		now - Math.floor(new Date(state.lastShownAt).getTime() / 1000) <
			OFFER_PAUSE_SECONDS
	) {
		return false;
	}
	if (!(await mailDeliveryConfigured())) return false;
	return (
		(await getPasskeyStore().countOf(bucket._id, user._id)) <
		PASSKEYS_PER_PERSON
	);
}
