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

const NOTICES: Record<string, string> = {
	[NOTICE_VERIFY]:
		'Check your inbox — we have emailed you a link to verify your address. You will be able to sign in once you have opened it.',
	[NOTICE_FEDERATION_ABORTED]:
		'Sign-in with your identity provider was not completed. You can try again, or sign in with your password.'
};

// No trimming, no case folding, no normalisation: an identifier is either one the server minted or it is
// nothing at all.
export function resolveNotice(value?: string): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	return NOTICES[value];
}
