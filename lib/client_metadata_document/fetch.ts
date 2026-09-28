import {
	EgressRefused,
	guardedFetch,
	isBlockedAddress,
	readBounded,
	resolver
} from '../shared/egress.js';
import { parseClientIdentifierUrl } from './identifier.js';

/*
 * Retrieving a client description document on behalf of an unauthenticated caller.
 *
 * The governing draft is explicit that an authorization server accepting a URL-shaped `client_id`
 * "takes a URL as input from an unknown client and fetches that URL", and that a malicious client can
 * use it to reach "private administration endpoints the authorization server has access to". The
 * egress rules that answer that — the address check on every hop, redirects followed by hand, the
 * time bound and the byte bound — live in `lib/shared/egress.ts`, the boundary every client-supplied
 * address goes through. What is this document's own:
 *
 *  1. The identifier's form, delegated to `identifier.ts`, before anything is resolved.
 *  2. Redirects that stay on https: the document's identity is its https URL.
 *  3. The 5 KB bound the draft recommends.
 *
 * What it deliberately does NOT do is decide whether the document is a valid client. That is
 * `validate.ts`, and separating them means this file can be read for one question only: can a caller
 * make this server talk to something it should not.
 */

/* Re-exported for the specs that drive the resolution seam and the range table from here. */
export { isBlockedAddress, resolver };

/* The draft's §6.6 recommendation, adopted rather than invented. */
export const MAX_DOCUMENT_BYTES = 5 * 1024;

/*
 * A host that accepts a connection and then says nothing must not hold an authorization request open.
 * Short because a client description document is a small static file; a host that cannot serve one in
 * two seconds is not one an end-user should be kept waiting on.
 */
export const FETCH_TIMEOUT_MS = 2_000;

/*
 * The draft permits a chain; nothing legitimate needs a long one. Four is enough for a canonical-URL
 * redirect and a CDN hop, and short enough that a loop is refused in milliseconds.
 */
export const MAX_REDIRECTS = 4;

export type FetchFailure =
	| 'bad_identifier'
	| 'unresolvable'
	| 'blocked_address'
	| 'bad_redirect'
	| 'too_many_redirects'
	| 'status'
	| 'too_large'
	| 'timeout'
	| 'unreachable';

export type FetchResult =
	| {
			readonly ok: true;
			readonly body: string;
			/* What the response said about reuse, for the cache to interpret. Raw, not parsed. */
			readonly cacheControl: string | null;
			readonly expires: string | null;
	  }
	| { readonly ok: false; readonly reason: FetchFailure };

/*
 * Retrieves a document, or says why not. Never throws: a caller is deciding whether to admit a client,
 * and an exception escaping into that decision would turn an unknown client into a 500.
 */
export async function fetchClientDocument(
	identifier: string
): Promise<FetchResult> {
	const parsed = parseClientIdentifierUrl(identifier);
	if (!parsed.ok) return { ok: false, reason: 'bad_identifier' };

	try {
		const response = await guardedFetch(parsed.url, {
			headers: { accept: 'application/json' },
			timeoutMs: FETCH_TIMEOUT_MS,
			maxRedirects: MAX_REDIRECTS,
			/*
			 * A redirect destination is held to the scheme rule but not to the rest of §3: the document
			 * lives wherever the host says, and only the `client_id` *inside* it has to match the
			 * identifier the client presented. That equality check is `validate.ts`'s, and it is what
			 * makes a redirect harmless.
			 */
			httpsRedirectsOnly: true
		});

		if (!response.ok) return { ok: false, reason: 'status' };

		return {
			ok: true,
			body: await readBounded(response, MAX_DOCUMENT_BYTES),
			cacheControl: response.headers.get('cache-control'),
			expires: response.headers.get('expires')
		};
	} catch (err) {
		if (err instanceof EgressRefused) return { ok: false, reason: err.reason };
		return { ok: false, reason: 'unreachable' };
	}
}
