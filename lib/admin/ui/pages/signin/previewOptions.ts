import type { FederationProvider } from '../../../../federation/types.js';
import {
	signInOptionsOf,
	type LoginOptions
} from '../../../../interactions/signInOptions.js';

/* The switches of the Sign-in tab the first screen depends on, as drafted — saved or not. */
export interface PreviewDraft {
	passwordLogin: boolean;
	registrationOpen: boolean;
	totpRequired: boolean;
}

/*
 * What the bucket's sign-in page would show with the tab's draft (specs/091), decided by the rule the server
 * renders the page with, never by a copy of it.
 *
 * The provider list is the one `GET …/federation` answered, which the server sends in sign-in order (specs/088
 * R10). Its ids are therefore the whole order, and handing them over as `signInOrder` makes the rule reproduce
 * that list exactly. Leaving the order out would not: the rule would fall back to the catalogue's ranking, which
 * is wrong for any bucket someone has reordered.
 */
export function previewOptions({
	bucketId,
	draft,
	providers,
	federationOn
}: {
	bucketId: string;
	draft: PreviewDraft;
	providers: readonly FederationProvider[];
	federationOn: boolean;
}): LoginOptions {
	return signInOptionsOf(
		bucketId,
		{
			...draft,
			federation: [...providers],
			signInOrder: providers.map((provider) => provider.id)
		},
		federationOn
	);
}
