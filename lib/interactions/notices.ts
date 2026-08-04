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

const NOTICES: Record<string, string> = {
	[NOTICE_VERIFY]:
		'Check your inbox — we have emailed you a link to verify your address. You will be able to sign in once you have opened it.'
};

// No trimming, no case folding, no normalisation: an identifier is either one the server minted or it is
// nothing at all.
export function resolveNotice(value?: string): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	return NOTICES[value];
}
