import { knownProviderByIssuer } from '../consts/known_providers.js';
import { discover, type ProviderMetadata } from './discovery.js';
import type { FederationProvider } from './types.js';

/*
 * Where this server sends a user, and where it exchanges what they come back with — for a provider that
 * publishes those facts and for one that does not.
 *
 * The authorization leg has always read them from the provider's own metadata, on the principle that the
 * provider already declares what it supports and a setting would only let an operator contradict it. That
 * principle is intact; one recognised provider simply declares nothing, because it publishes no metadata
 * document at all. For that one the endpoints come from the catalogue entry, which is the only other place
 * they could honestly come from — they are facts about that provider, not choices a deployment makes.
 */

export async function upstreamMetadata(
	provider: FederationProvider
): Promise<ProviderMetadata> {
	const entry = knownProviderByIssuer(provider.issuer);
	if (entry?.protocol.kind !== 'profile_api') {
		return discover(provider.issuer);
	}

	return {
		issuer: provider.issuer,
		authorizationEndpoint: entry.protocol.authorizationEndpoint,
		tokenEndpoint: entry.protocol.tokenEndpoint,
		/*
		 * Empty, and that is not a gap being papered over: this provider issues no signed assertion, so
		 * there is no key set to fetch and no signature to check. Nothing on the profile-API path reads
		 * either field, and leaving them empty is what makes a misrouted read fail loudly.
		 */
		jwksUri: '',
		signingAlgValues: [],
		/*
		 * Left empty deliberately even though this provider does support the binding. Support is read from
		 * the catalogue entry, which is the whole point of stating it there — putting it here too would be a
		 * second copy of the same fact, and the two would disagree the first time one was edited.
		 */
		codeChallengeMethods: [],
		tokenAuthMethods: ['client_secret_post']
	};
}
