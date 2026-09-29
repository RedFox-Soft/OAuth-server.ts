import {
	getProjectStore,
	getProtectedResourceStore
} from '../adapters/index.js';
import type { ProtectedResource } from '../adapters/types.js';
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
 * Two point reads at most, both inside one namespace, and the order is what makes a significant
 * trailing slash mean anything.
 *
 * The exact spelling is tried first, so a resource declared as `.../mcp/` answers a request for
 * `.../mcp/` rather than being shadowed by its slash-free sibling. Only then is the slash-free form
 * tried, which is what lets a client that dropped the slash — as the MCP specification tells clients
 * to prefer — still reach an ordinary declaration.
 *
 * A resource whose slash is significant can never be reached by the second read: its stored identifier
 * ends in a slash and the slash-free candidate does not, so the two cannot collide. That is why no extra
 * guard is needed here, and why one would be dead code if added.
 *
 * The namespace is the caller's to supply, from the address the request arrived at, and nothing here
 * falls back to another one: a declaration in another tenant's namespace does not exist for this
 * request, which is what stops one tenant's declaration shadowing or redirecting another's.
 */
export async function findDeclaredResource(
	identifier: string,
	namespace: string
): Promise<ProtectedResource | undefined> {
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
		const resource = await store.find(namespace, candidate);
		if (resource) return resource;
	}

	return undefined;
}

export async function resolveDeclaredResource(
	identifier: string,
	namespace: string
): Promise<DeclaredResourceInfo | undefined> {
	const resource = await findDeclaredResource(identifier, namespace);
	if (!resource) return undefined;

	return {
		audience: resource.identifier,
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

/*
 * Whether a client may hold a token for this resource that acts for nobody — the client credentials
 * grant, where no end user signs in and nobody consents. A declared resource belongs to the project
 * that declared it, and such a token goes to that project's clients alone; otherwise any client of any
 * tenant, or one that registered itself, could mint a token carrying another tenant's audience and
 * scopes. An identifier nobody declared is not this function's question — the built-in MCP audience and
 * a deployment's override answer for themselves — so it is permitted here and resolved as before.
 */
export async function machineTokenPermitted(
	identifier: string,
	clientId: string,
	namespace: string
): Promise<boolean> {
	const resource = await findDeclaredResource(identifier, namespace);
	if (!resource) return true;

	const project = await getProjectStore().findByClientId(clientId);
	return project?._id === resource.projectId;
}
