// Bounds of signing in with a passkey and of a person's own passkeys (specs/139). Kept in one place so the ceremony, the
// account page, the limits and the tests share them; the only import is another leaf of constants.

/*
 * How long a prepared ceremony works: the challenge on a sign-in page, and an add or a removal prepared on the account
 * page. The options ask the browser for the same five minutes (`timeout: 300000`); a challenge that outlives the
 * prompt it was made for is only something to replay.
 */
export const CEREMONY_SECONDS = 5 * 60;

/*
 * A "recent" sign-in on the account page, for renaming a passkey and for the strong sign-in that adds or removes one
 * without a mailed link. The same fifteen minutes as two-step verification's own page, so one sign-in opens both parts
 * of "Sign-in and security".
 */
export { FRESH_SECONDS } from '../totp/consts.js';

/*
 * How long the "This wasn't me" link in the mail about an added passkey works. The same three days as the link about a
 * new authenticator app (lib/totp/consts.ts DISOWN_TTL_SECONDS): long enough for someone who reads mail once a day or
 * over a weekend.
 */
export const NOT_ME_SECONDS = 72 * 60 * 60;

/*
 * How long the "Yes, this was me" link in the mail about a conditional passkey works (specs/141): the same three days as
 * "This wasn't me" beside it, so one sentence covers both links.
 */
export const CONFIRM_SECONDS = 72 * 60 * 60;

/*
 * How long a showing of the passkey offer keeps it away from the person, in every app and browser of the project
 * (specs/141 research R4). The thirty days comparable products use.
 */
export const OFFER_PAUSE_SECONDS = 30 * 24 * 60 * 60;

/*
 * Passkeys one person may hold in one project. Twenty covers a phone, a laptop, a tablet and a few security keys with
 * room to spare, and bounds the list a page renders and the `excludeCredentials` an add sends to the browser.
 */
export const PASSKEYS_PER_PERSON = 20;

/*
 * Failed passkey sign-ins tolerated from one caller address in one UTC hour, after which every attempt from it is
 * refused before any lookup. Only failures count, so an office behind one address signing in at nine o'clock is never
 * refused; nothing is typed at this door, so thirty is far above what a person with a wrong passkey produces.
 */
export const FAILURES_PER_CALLER_PER_HOUR = 30;

/*
 * The largest `credential` field the sign-in and add forms accept, in characters. A real assertion or attestation is
 * a few kilobytes at most (a credential id is at most 1023 bytes); anything larger is refused before it is parsed.
 */
export const CREDENTIAL_FIELD_MAX = 16384;

/* The longest name a person may give a passkey, in characters, after trimming. */
export const NAME_MAX = 64;

/*
 * Pre-account passkey registration email link / 6-digit code lifetime (specs/145 Q2=A): ten minutes, matching
 * self-service recovery.
 */
export const REGISTRATION_CHALLENGE_SECONDS = 10 * 60;

/* Maximum wrong 6-digit code attempts during passkey registration before the challenge is exhausted. */
export const REGISTRATION_CODE_MAX_ATTEMPTS = 5;

/* Browser-bound self-service passkey recovery link lifetime (specs/145 S3): ten minutes. */
export const RECOVERY_LINK_SECONDS = 10 * 60;

/*
 * Duration a passkey created via self-service email recovery is capped at `multi_factor` ACR rather than
 * `phishing_resistant` (specs/145 Q1=A): 72 hours, unless confirmed earlier with another full passkey.
 */
export const RECOVERY_ACR_CAP_SECONDS = 72 * 60 * 60;

/* Administrator-sent passkey enrollment link lifetime (specs/145 S14): 24 hours, usable in any browser. */
export const ADMIN_LINK_SECONDS = 24 * 60 * 60;

/*
 * Minimum age of an account's current email address before an administrator may send a passkey enrollment link
 * (specs/145): 7 days, blocking same-week email swap + passkey takeover.
 */
export const EMAIL_CHANGE_LINK_COOLDOWN_SECONDS = 7 * 24 * 60 * 60;

/* "Ask everyone to create a passkey" campaign grace bounds (specs/145): up to 3 skips within 14 days of first shown. */
export const CAMPAIGN_MAX_SKIPS = 3;
export const CAMPAIGN_WINDOW_SECONDS = 14 * 24 * 60 * 60;

/* Per-target throttle bounds shared by passkey registration, recovery, and admin enrollment links (1/min, 5/day). */
export const PASSKEY_LINK_COOLDOWN_SECONDS = 60;
export const PASSKEY_LINK_DAILY_CAP = 5;
export const PASSKEY_LINK_WINDOW_SECONDS = 24 * 60 * 60;
