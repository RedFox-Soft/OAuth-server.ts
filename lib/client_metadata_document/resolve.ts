import { ApplicationConfig } from '../configs/application.js';
import { parseClientIdentifierUrl } from './identifier.js';
import { fetchClientDocument } from './fetch.js';
import { validateClientDocument } from './validate.js';
import { cachedDocument, rememberDocument, reuseSecondsFor } from './cache.js';

/*
 * The whole of "resolve a URL-shaped client_id to client metadata", in one place: the form rules, the
 * guarded retrieval, the document validation, and the bounded reuse — in that order, and each one able
 * to say no.
 *
 * Returns metadata, never a client. Whether that metadata makes a usable client is the client model's
 * question, asked afterwards by the caller, so a document cannot skip a single check a registered
 * client faces. Nothing is written to the client store at any point: that is the property SC-010 pins,
 * and the reason a document identifier costs an operator nothing to accept.
 */

export async function resolveClientDocument(
	identifier: string
): Promise<Record<string, unknown> | undefined> {
	/*
	 * Gated, and off by default. Accepting a URL as a client id is what gives an unauthenticated caller
	 * the ability to make this server issue an outbound request, which is a capability a deployment
	 * consents to rather than inherits — the same reason `registration.enabled` defaults off.
	 */
	if (!ApplicationConfig['clientIdMetadataDocument.enabled']) return undefined;

	const parsed = parseClientIdentifierUrl(identifier);
	if (!parsed.ok) return undefined;

	/*
	 * Keyed on the identifier the client presented rather than on the URL finally fetched. They differ
	 * when a host redirects, and the identifier is what the next request will arrive with.
	 */
	const cached = cachedDocument(identifier);
	if (cached) return cached;

	const retrieved = await fetchClientDocument(identifier);
	if (!retrieved.ok) return undefined;

	const validated = validateClientDocument(retrieved.body, identifier);
	/*
	 * Nothing is remembered on either failure path, which is the draft's rule stated as control flow:
	 * an error response and a malformed document are both simply never handed to the store. A cached
	 * failure would pin a transient outage — or one attacker-supplied malformed document — in front of
	 * a working one for the life of the entry.
	 */
	if (!validated.ok) return undefined;

	rememberDocument(
		identifier,
		validated.metadata,
		reuseSecondsFor(retrieved.cacheControl, retrieved.expires)
	);

	return validated.metadata;
}
