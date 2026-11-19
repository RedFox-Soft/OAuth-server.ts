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
