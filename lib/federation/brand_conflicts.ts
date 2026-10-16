import {
	KNOWN_PROVIDERS,
	knownProviderByIssuer
} from '../consts/known_providers.js';

/*
 * Setups that put a confusing button on a project's sign-in page (specs/105), worked out from the providers
 * alone. Import-free apart from the catalogue, because the console's Sign-in tab runs it in a browser over the
 * list it has already read.
 *
 * - `duplicate_brand`: two enabled connections to a provider a project needs only once (Google, Apple, GitHub).
 *   Both buttons must carry the brand's own wording, so only a second line tells them apart.
 * - `named_like_brand`: an enabled provider this server does not recognise, named like one it does. Its button
 *   would read "Sign in with Google" without Google's mark or wording rules — what a phishing page looks like.
 *
 * Disabled providers never count: they have no button.
 */
export type BrandConflict = 'duplicate_brand' | 'named_like_brand';

export function brandConflicts(
	providers: readonly {
		id: string;
		issuer: string;
		displayName: string;
		enabled: boolean;
	}[]
): Map<string, BrandConflict[]> {
	const enabled = providers.filter((provider) => provider.enabled);
	const brands = enabled.map((provider) => ({
		provider,
		known: knownProviderByIssuer(provider.issuer)
	}));
	const brandNames = new Set(
		KNOWN_PROVIDERS.map((entry) => entry.displayName.toLowerCase())
	);

	const conflicts = new Map<string, BrandConflict[]>();
	for (const { provider, known } of brands) {
		const found: BrandConflict[] = [];
		if (
			known?.oneConnectionPerProject === true &&
			brands.some(
				(other) => other.provider !== provider && other.known === known
			)
		) {
			found.push('duplicate_brand');
		}
		if (!known && brandNames.has(provider.displayName.trim().toLowerCase())) {
			found.push('named_like_brand');
		}
		if (found.length > 0) conflicts.set(provider.id, found);
	}
	return conflicts;
}
