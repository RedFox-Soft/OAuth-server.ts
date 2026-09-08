import { getProtectedResourceStore } from '../adapters/index.js';
import { canonicalizeResourceIdentifier } from './canonical.js';

/*
 * Resolving a requested resource indicator to the descriptor the token path needs.
 *
 * The shape returned is `ResourceServer`'s constructor argument, deliberately: a declared resource
 * reaches the grant handlers through exactly the same object an addon override would return, so
 * nothing downstream can tell the two apart and nothing downstream needed changing.
 *
 * There is no cache. A deleted declaration has to stop issuance on the *next* request — the property
 * `test/resources/issuance.spec.ts` pins — and a memo in front of a primary-key read would buy
 * microseconds at the cost of that guarantee. `tryFindClient` reads the adapter every time for the
 * same reason, after a TTL-less client memo once served a stale client to the admin plane.
 */

export interface DeclaredResourceInfo {
	readonly audience: string;
	readonly scope: string;
	readonly accessTokenFormat: 'jwt' | 'opaque';
	readonly accessTokenTTL: number;
}

/*
 * Two point reads at most, and the order is what makes a significant trailing slash mean anything.
 *
 * The exact spelling is tried first, so a resource declared as `.../mcp/` answers a request for
 * `.../mcp/` rather than being shadowed by its slash-free sibling. Only then is the slash-free form
 * tried, which is what lets a client that dropped the slash — as the MCP specification tells clients
 * to prefer — still reach an ordinary declaration.
 *
 * A resource whose slash is significant can never be reached by the second read: its stored id ends
 * in a slash and the slash-free candidate does not, so the two cannot collide. That is why no extra
 * guard is needed here, and why one would be dead code if added.
 */
export async function resolveDeclaredResource(
	identifier: string
): Promise<DeclaredResourceInfo | undefined> {
	const exact = canonicalizeResourceIdentifier(identifier, {
		trailingSlashSignificant: true
	});
	if (!exact.ok) return undefined;

	const trimmed = canonicalizeResourceIdentifier(identifier);
	if (!trimmed.ok) return undefined;

	const store = getProtectedResourceStore();

	const candidates =
		exact.identifier === trimmed.identifier
			? [exact.identifier]
			: [exact.identifier, trimmed.identifier];

	for (const candidate of candidates) {
		const resource = await store.find(candidate);
		if (!resource) continue;

		return {
			audience: resource._id,
			/*
			 * Joined here rather than stored joined. A space-delimited string is the wire shape the
			 * `ResourceServer` descriptor speaks; an array is the storage shape. Translating at this one
			 * seam is what keeps a scope containing a space from being silently declarable.
			 */
			scope: resource.scopes.join(' '),
			accessTokenFormat: resource.tokenFormat,
			accessTokenTTL: resource.accessTokenTTL
		};
	}

	return undefined;
}
