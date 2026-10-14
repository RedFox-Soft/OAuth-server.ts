import type { Language } from '../i18n/languages.js';
import { SIGN_IN_TEXTS, type SignInTexts } from '../i18n/texts/signIn/index.js';

/*
 * The login page's informational messages. A request selects one by identifier; it never supplies the
 * text. That direction is the whole point: a login page that renders a string taken from its own query
 * string is a phishing surface, and an identifier the server did not mint has no near misses — it is
 * simply not a notice.
 *
 * The vocabulary is closed and lives here so a producer (`buildUILoginPath`) and the consumer (the GET
 * route) cannot drift apart. That drift is exactly the defect this fixes: the registration flow has been
 * redirecting to `?notice=verify` since it was written, and nothing has ever read it.
 */

export const NOTICE_VERIFY = 'verify';

/*
 * A federated sign-in that came back without completing — the user cancelled at their provider, or the
 * provider refused. Informational rather than an error: nothing the user did on *this* page failed, and the
 * page they land on offers both a retry and the password form.
 *
 * It exists because the login page cannot be *rendered* at the callback URL. The client bundle derives both
 * the page and the interaction id from `window.location.pathname`, so a login document served at
 * /federation/callback hydrates into an empty root — silently, in a browser only. A redirect to the real
 * login path is the fix; this identifier is how the message survives it without any request text reaching
 * the page.
 */
export const NOTICE_FEDERATION_ABORTED = 'federation_aborted';

/*
 * A federated sign-in whose address matched an account that holds only a password. The identity is
 * linked once this interaction's sign-in completes as that account, so the page asks for exactly that.
 */
export const NOTICE_FEDERATION_LINK = 'federation_link';

/*
 * The answers to "send the link again" (`POST /ui/:uid/verification/resend`). That route redirects here
 * rather than rendering the page itself, for the federation callback's reason above: the client bundle
 * reads the page from the path, and a login document served at …/verification/resend never hydrates.
 */
export const NOTICE_VERIFY_RESENT = 'verify_resent';
export const NOTICE_VERIFY_RECENT = 'verify_recent';
export const NOTICE_VERIFY_UNSENT = 'verify_unsent';

// The words live in the sign-in catalogue (lib/i18n/texts/signIn), in every language; this maps an identifier to
// its entry.
const NOTICES: Record<string, keyof SignInTexts['notices']> = {
	[NOTICE_VERIFY]: 'verify',
	[NOTICE_FEDERATION_ABORTED]: 'federationAborted',
	[NOTICE_VERIFY_RESENT]: 'verifyResent',
	[NOTICE_VERIFY_RECENT]: 'verifyRecent',
	[NOTICE_VERIFY_UNSENT]: 'verifyUnsent',
	[NOTICE_FEDERATION_LINK]: 'federationLink'
};

// No trimming, no case folding, no normalisation: an identifier is either one the server minted or it is
// nothing at all. `Object.hasOwn`, so `toString` and its kin are not identifiers either.
export function resolveNotice(
	value: string | undefined,
	language: Language = 'en'
): string | undefined {
	if (value === undefined || !Object.hasOwn(NOTICES, value)) {
		return undefined;
	}
	return SIGN_IN_TEXTS[language].notices[NOTICES[value]];
}
