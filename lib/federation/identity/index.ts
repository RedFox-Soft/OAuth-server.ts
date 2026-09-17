import { knownProviderByIssuer } from '../../consts/known_providers.js';
import type { IdentityRequest, UpstreamIdentity } from './contract.js';
import { oidcIdentity } from './oidc.js';
import { profileApiIdentity } from './profile_api.js';

/*
 * **The seam.** Who signed in, as a subject and a set of claims.
 *
 * Everything below this — `resolve.ts`'s decision ladder, linking, provisioning, the domain rules, the
 * session — already took a plain claims record and knew nothing about ID tokens. That is what made a
 * second protocol possible at all: one of the four recognised providers issues no identity assertion and
 * publishes no metadata, and it needs no change whatsoever to the part of this subsystem where a
 * divergence would be a vulnerability rather than an inconsistency.
 *
 * Dispatch is a **lookup on the matched catalogue entry's protocol**, never a branch on a provider's name
 * or catalogue id. Nothing on the stored provider says which protocol it speaks; it is resolved from the
 * issuer on each use, exactly as the login page resolves the button's mark. So a provider configured by
 * hand years ago gets the right treatment, there was no migration, and no sign-in decision is *able* to
 * depend on how a provider came to exist.
 */

export {
	IdentityError,
	type IdentityRequest,
	type IdentityStage,
	type UpstreamIdentity
} from './contract.js';

export async function identityFor(
	request: IdentityRequest
): Promise<UpstreamIdentity> {
	const entry = knownProviderByIssuer(request.provider.issuer);
	const protocol = entry?.protocol ?? { kind: 'oidc' as const };

	return protocol.kind === 'profile_api'
		? profileApiIdentity(request, protocol)
		: oidcIdentity(request);
}
