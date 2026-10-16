import { knownProviderByIssuer } from '../../../../consts/known_providers.js';

/*
 * The name a provider's sign-in button says: the brand's for a recognised provider, the administrator's for any
 * other — which is the name a warning about that button has to use.
 */
export function brandNameOf(provider: {
	issuer: string;
	displayName: string;
}): string {
	return (
		knownProviderByIssuer(provider.issuer)?.displayName ?? provider.displayName
	);
}
