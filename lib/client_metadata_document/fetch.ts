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
 * egress rules that answer that — the address check, the time bound and the byte bound — live in
 * `lib/shared/egress.ts`, the boundary every client-supplied address goes through. What is this
 * document's own:
 *
 *  1. The identifier's form, delegated to `identifier.ts`, before anything is resolved.
 *  2. One request, answered 200 or not at all. Draft -02 §5: the document "MUST be served with a 200 OK
 *     HTTP status code", the server "MUST treat all other HTTP status codes as an error response" and
 *     "MUST NOT automatically follow HTTP redirects". A document lives at its identifier; a redirect is a
 *     refusal, and its destination is never asked for.
 *  3. The 5 KB bound the draft recommends (§8.7).
 *
 * What it deliberately does NOT do is decide whether the document is a valid client. That is
 * `validate.ts`, and separating them means this file can be read for one question only: can a caller
 * make this server talk to something it should not.
 */

/* Re-exported for the specs that drive the resolution seam and the range table from here. */
export { isBlockedAddress, resolver };

/* The draft's §8.7 recommendation, adopted rather than invented. */
export const MAX_DOCUMENT_BYTES = 5 * 1024;

/*
 * A host that accepts a connection and then says nothing must not hold an authorization request open.
 * Short because a client description document is a small static file; a host that cannot serve one in
 * two seconds is not one an end-user should be kept waiting on.
 */
export const FETCH_TIMEOUT_MS = 2_000;

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
			/* A redirect comes back unread, and fails the status test below like any other non-200. */
			maxRedirects: 0
		});

		if (response.status !== 200) return { ok: false, reason: 'status' };

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
