import { knownProviderByIssuer } from '../consts/known_providers.js';
import type { ConnectionCorrelation } from '../adapters/types.js';
import type { FederationProvider } from '../federation/types.js';

/*
 * A claim name an administrator may choose. Restricted to the characters claim names actually use, because
 * the value is read from the upstream ID token by this name and shown back in the console.
 */
export const CLAIM_NAME_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;

/*
 * The rule a new connection starts with.
 *
 * Microsoft's `oid` is the object id Entra also sends to SCIM as `externalId`, and it is stable across
 * every application in the tenant. Its `sub` is pairwise — different per application — so it can never be
 * the key (issue #62). Every other provider starts from `preferred_username` ↔ `userName`, which is what
 * Okta sends; `sub` is never a default, because whether a provider's subjects are pairwise is not
 * something this server can know.
 */
export function defaultCorrelationFor(
	provider: Pick<FederationProvider, 'issuer'>
): ConnectionCorrelation {
	if (knownProviderByIssuer(provider.issuer)?.catalogueId === 'microsoft') {
		return { claim: 'oid', attribute: 'externalId' };
	}
	return { claim: 'preferred_username', attribute: 'userName' };
}
