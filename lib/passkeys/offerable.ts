import { getPasskeyStore } from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import epochTime from '../helpers/epoch_time.js';
import { mailDeliveryConfigured } from '../mail/mailer.js';
import { passkeysAccepted } from './accepted.js';
import {
	CAMPAIGN_MAX_SKIPS,
	CAMPAIGN_WINDOW_SECONDS,
	OFFER_PAUSE_SECONDS,
	PASSKEYS_PER_PERSON
} from './consts.js';
import { relyingPartyOf } from './relying_party.js';

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
 *
 * Never on the administrators' project (specs/144 FR-002): administrators add passkeys deliberately from the console
 * after strong verification or a mailed link, and never hold conditional passkeys.
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
	if (bucket._id === ADMIN_BUCKET_ID) return false;
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

/*
 * Whether the person may create a passkey from the page that turns them away from an application requiring one (specs/142
 * research R8): the safety half of the offer's conditions — the project accepts passkeys, the address is confirmed, mail
 * works, they hold fewer than twenty, and "This wasn't me" is not holding them back. The offer's own opt-outs (the
 * project's setting, "Don't ask again", the 30-day pause) do not apply: this is the person's own step, as on their page.
 *
 * Never on the administrators' project (specs/144 FR-017): console passkey refusal never creates a passkey on the spot.
 */
export async function mayCreateAfterSignIn(
	bucket: UserBucket,
	user: User
): Promise<boolean> {
	if (bucket._id === ADMIN_BUCKET_ID) return false;
	if (!passkeysAccepted(bucket) || !user.verified) return false;
	if (user.passkeyOffer?.held === true) return false;
	if (!(await mailDeliveryConfigured())) return false;
	return (
		(await getPasskeyStore().countOf(bucket._id, user._id)) <
		PASSKEYS_PER_PERSON
	);
}

export interface CampaignSkipState {
	canSkip: boolean;
	skipsUsed: number;
	skipsLeft: number;
	maxSkips: number;
}

/*
 * Computes remaining skips for a user in the `passkeyRequired` campaign (specs/145): up to 3 skips within 14 days of
 * first presentation. Once either bound is reached, skipping is no longer allowed on passkey-capable devices.
 */
export function campaignSkipState(
	user: Pick<User, 'passkeyPrompt'>,
	nowSeconds: number = epochTime()
): CampaignSkipState {
	const prompt = user.passkeyPrompt;
	if (!prompt) {
		return {
			canSkip: true,
			skipsUsed: 0,
			skipsLeft: CAMPAIGN_MAX_SKIPS,
			maxSkips: CAMPAIGN_MAX_SKIPS
		};
	}
	const firstShownSeconds = Math.floor(
		new Date(prompt.firstShownAt).getTime() / 1000
	);
	const withinWindow = nowSeconds - firstShownSeconds < CAMPAIGN_WINDOW_SECONDS;
	const skipsUsed = prompt.skips;
	const skipsLeft = withinWindow
		? Math.max(0, CAMPAIGN_MAX_SKIPS - skipsUsed)
		: 0;
	return {
		canSkip: withinWindow && skipsLeft > 0,
		skipsUsed,
		skipsLeft,
		maxSkips: CAMPAIGN_MAX_SKIPS
	};
}

/*
 * Whether the project-wide "Ask everyone to create a passkey" campaign should prompt this user after a password
 * sign-in (specs/145): non-admin, passkeys and `passkeyRequired` both on, mail configured, not held back by
 * "This wasn't me", and the user holds zero working passkeys for the project's current RP ID.
 */
export async function campaignDue(
	bucket: UserBucket,
	user: User
): Promise<boolean> {
	if (bucket._id === ADMIN_BUCKET_ID) return false;
	if (!passkeysAccepted(bucket) || bucket.passkeyRequired !== true)
		return false;
	if (user.passkeyOffer?.held === true) return false;
	if (!(await mailDeliveryConfigured())) return false;
	const rpId = relyingPartyOf(bucket).rpId;
	const held = await getPasskeyStore().listOf(bucket._id, user._id);
	const hasWorking = held.some(
		(passkey) => passkey.copiedAt === undefined && passkey.rpId === rpId
	);
	return !hasWorking && held.length < PASSKEYS_PER_PERSON;
}
