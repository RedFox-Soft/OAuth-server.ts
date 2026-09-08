import { snakeToCanonical } from '../models/client/wire.js';

/*
 * Turning a retrieved document into client metadata, or refusing it.
 *
 * Deliberately separate from `fetch.ts`: that file answers "may this server talk to it", this one
 * answers "may this document speak for a client". Keeping them apart is what lets the egress boundary
 * be reviewed on its own, and it is why nothing here knows about addresses or redirects.
 *
 * Also deliberately separate from `validateClient`. This checks the rules that come from the document
 * *being* a document — the identifier equality, the required properties, the forbidden authentication
 * methods — and hands back plain metadata. Whether that metadata makes a usable client is the client
 * model's own question, asked afterwards, so a document cannot bypass a single check a registered
 * client faces.
 */

export type DocumentFailure =
	| 'not_json'
	| 'not_an_object'
	| 'missing_property'
	| 'identifier_mismatch'
	| 'bad_redirect_uris'
	| 'symmetric_secret'
	| 'missing_jwks';

export type DocumentResult =
	| { readonly ok: true; readonly metadata: Record<string, unknown> }
	| {
			readonly ok: false;
			readonly reason: DocumentFailure;
			/* Which property was at fault, where naming one helps. */
			readonly detail?: string;
	  };

const REQUIRED = ['client_id', 'client_name', 'redirect_uris'] as const;

/*
 * §4.1, a MUST NOT: no method built on a shared symmetric secret. A client identified by a document
 * it hosts itself was never issued a secret, so a document claiming one of these is either mistaken
 * or trying to have this server accept a credential nobody holds.
 *
 * Matched by shape rather than by list membership, because the draft's wording is "or any other
 * method based around a shared symmetric secret" — an enumeration would go stale the first time a new
 * one is registered.
 */
function usesSymmetricSecret(method: string): boolean {
	return method.startsWith('client_secret_');
}

export function validateClientDocument(
	body: string,
	identifier: string
): DocumentResult {
	let parsed: unknown;
	try {
		parsed = JSON.parse(body);
	} catch {
		return { ok: false, reason: 'not_json' };
	}

	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
		return { ok: false, reason: 'not_an_object' };
	}

	const document = { ...(parsed as Record<string, unknown>) };

	for (const property of REQUIRED) {
		if (document[property] === undefined) {
			return { ok: false, reason: 'missing_property', detail: property };
		}
	}

	/*
	 * Byte-for-byte, against the URL the document was retrieved from — no canonicalization, no case
	 * folding, no trailing-slash tolerance. This is the check that makes a document identifier mean
	 * anything: without it, hosting a document that names somebody else's identifier would let an
	 * attacker borrow a well-known client's name while supplying their own redirect target.
	 *
	 * Tolerating near matches here would undo the strictness the identifier rules established. Two
	 * spellings that resolve to one document are exactly the case `identifier.ts` refuses, and the
	 * reason it refuses on the raw input rather than the parsed URL.
	 */
	if (document.client_id !== identifier) {
		return { ok: false, reason: 'identifier_mismatch' };
	}

	const redirectUris = document.redirect_uris;
	if (
		!Array.isArray(redirectUris) ||
		redirectUris.length === 0 ||
		redirectUris.some(
			(uri) => typeof uri !== 'string' || uri.trim().length === 0
		)
	) {
		return { ok: false, reason: 'bad_redirect_uris' };
	}

	const method = document.token_endpoint_auth_method;
	if (typeof method === 'string') {
		if (usesSymmetricSecret(method)) {
			return { ok: false, reason: 'symmetric_secret' };
		}
		/*
		 * A key-proving method with no published key location would be accepted here and then fail at
		 * the token endpoint, where an operator has no way to trace the refusal back to the document.
		 */
		if (
			method === 'private_key_jwt' &&
			typeof document.jwks_uri !== 'string' &&
			document.jwks === undefined
		) {
			return { ok: false, reason: 'missing_jwks' };
		}
	}

	/*
	 * A secret in a world-readable, self-hosted document is not a secret. Dropped rather than refused:
	 * the harm is entirely in honouring it, and a document that carries one by mistake should still be
	 * able to identify a public client. Dropped *before* translation so no canonical `clientSecret`
	 * can reach the model either.
	 */
	delete document.client_secret;
	delete document.client_secret_expires_at;

	return { ok: true, metadata: snakeToCanonical(document) };
}
