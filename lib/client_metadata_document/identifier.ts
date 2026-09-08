/*
 * Whether a `client_id` is a URL naming a client description document, and whether it is a *usable*
 * one.
 *
 * Everything here is decided from the string alone, before any network call. That is the security
 * property, not a performance one: a malformed identifier that reached the fetch layer would be a
 * free probe of whatever this server can reach, and the draft's §6.5 says an authorization server
 * accepting a URL from an unknown client is exactly an SSRF surface. Refusing on shape costs nothing.
 *
 * `not_a_url` is deliberately not a failure in the same sense as the rest. Every ordinary client id —
 * `admin-panel`, `client`, a URN — lands there, and the caller's job is to fall through to the normal
 * client lookup rather than to refuse. Conflating "this is not a document identifier" with "this
 * document identifier is malformed" would start refusing every client the server already has.
 *
 * Imports nothing. It is called from the client resolution path, which runs on every authorization and
 * token request.
 */

export type IdentifierFailure =
	| 'not_a_url'
	| 'not_https'
	| 'no_path'
	| 'dot_segment'
	| 'fragment'
	| 'credentials';

export type IdentifierResult =
	| { readonly ok: true; readonly url: URL }
	| { readonly ok: false; readonly reason: IdentifierFailure };

/*
 * The draft's §3 rules. Every one refuses the same identifier, so the order only decides which reason
 * an operator is shown — and two placements are deliberate for that. The scheme is checked first,
 * because a non-https URL is wrong whatever its path. The dot-segment rule runs before the missing-path
 * rule, because parsing resolves `/a/..` down to `/` and the traversal would otherwise be reported as
 * a missing path — true, but not the thing the caller did wrong.
 */
export function parseClientIdentifierUrl(id: string): IdentifierResult {
	const url = URL.parse(id);
	if (!url) return { ok: false, reason: 'not_a_url' };

	/*
	 * A relative-looking value can still parse when it happens to look like `scheme:rest`, so a
	 * successful parse is not yet a URL identifier. Only http(s) is even a candidate; anything else —
	 * `urn:`, `mailto:` — is an ordinary client id that happens to contain a colon.
	 */
	if (url.protocol !== 'https:' && url.protocol !== 'http:') {
		return { ok: false, reason: 'not_a_url' };
	}

	if (url.protocol !== 'https:') return { ok: false, reason: 'not_https' };

	/*
	 * Applied to the RAW input, not to the parsed pathname, and that is not a stylistic choice —
	 * checking the parsed form cannot work. URL parsing resolves dot segments away before anyone can
	 * look at them, percent-encoded ones included: `/a/%2e%2e/c.json` parses to `/c.json`, so a rule
	 * reading `url.pathname` would pass every traversal it was written to refuse. Verified, not assumed.
	 *
	 * The identifier must therefore be rejected on what the client actually sent. This matters beyond
	 * tidiness: two identifiers that differ textually but parse to the same document would both be
	 * accepted, while the `client_id` inside the document can only equal one of them — so the other
	 * would be an identifier a client could use and an operator could never allowlist by sight.
	 */
	const afterAuthority = id.replace(/^https?:\/\/[^/?#]*/i, '');
	const rawPath = afterAuthority.split(/[?#]/)[0];
	const rawSegments = rawPath.split('/').map((segment) => {
		try {
			return decodeURIComponent(segment);
		} catch {
			/* A malformed escape is not a dot segment; the parse above already accepted the URL. */
			return segment;
		}
	});
	if (rawSegments.some((segment) => segment === '.' || segment === '..')) {
		return { ok: false, reason: 'dot_segment' };
	}

	/*
	 * URL parsing gives a bare origin the pathname `/`, which the draft does not accept as a path
	 * component. Refusing it also refuses a client id that is effectively just a hostname, which would
	 * let whoever controls a domain speak for every application published on it.
	 */
	if (url.pathname === '' || url.pathname === '/') {
		return { ok: false, reason: 'no_path' };
	}

	if (id.includes('#') || url.hash !== '') {
		return { ok: false, reason: 'fragment' };
	}

	if (url.username !== '' || url.password !== '') {
		return { ok: false, reason: 'credentials' };
	}

	return { ok: true, url };
}

/*
 * Whether a caller should try to resolve this id as a document identifier at all.
 *
 * Separate from the full parse because the two questions have different answers for a malformed
 * https URL: it *looks* like a document identifier, so refusing it is right, while an ordinary client
 * id must fall through untouched. Callers use this to decide which of those they are in.
 */
export function looksLikeClientIdentifierUrl(id: string): boolean {
	const url = URL.parse(id);
	return (
		url !== null && (url.protocol === 'https:' || url.protocol === 'http:')
	);
}

/*
 * Whether a redirect target is a loopback address, in the forms a native client actually publishes.
 *
 * Single-sourced because two unrelated places ask it and the answer is security-relevant: the consent
 * screen warns an end-user that such a document cannot prove which local process will receive the
 * code, and the administrative permission route refuses to grant authority on that basis without an
 * acknowledgement. Two copies of the predicate would be two chances for one to stop recognising a
 * form — and the failure would be silent in both directions, a warning that stopped appearing and an
 * interlock that stopped engaging.
 */
export function isLoopbackRedirect(uri: string): boolean {
	const host = URL.parse(uri)?.hostname.toLowerCase();
	return (
		host === 'localhost' ||
		host === '127.0.0.1' ||
		host === '::1' ||
		host === '[::1]'
	);
}
