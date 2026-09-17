import { getBucketStore } from '../adapters/index.js';
import { enabledProviders } from '../federation/providers.js';
import {
	KNOWN_PROVIDERS,
	knownProviderByIssuer
} from '../consts/known_providers.js';
import { resolveBucketForRequest } from '../admin/auth/resolveBucket.js';

/*
 * What the login page needs to know about a bucket in order to render itself: whether it accepts a password
 * at all, and which providers it offers.
 *
 * One resolver, because four places need the same answer and must not disagree — the GET that renders the
 * page, the POST that re-renders it on a bad password, the federation callback that re-renders it on a
 * decline, and the doors that refuse when password sign-in is off. A page that offered a password form the
 * POST would refuse, or dropped the provider buttons on a re-render, is the drift this prevents.
 */

export interface LoginOptions {
	passwordLogin: boolean;
	/*
	 * Whether a password sign-in to this bucket must also carry a one-time code. Resolved here with
	 * everything else the password door needs, for the reason above: the login POST, the registration
	 * POST and both enrolment routes all ask this question, and a second lookup path is exactly the
	 * drift this module exists to prevent.
	 *
	 * Deliberately not rendered on the login page. Advertising the requirement before the password is
	 * known would say something about the accounts in this bucket to anyone who asks.
	 */
	totpRequired: boolean;
	/*
	 * Only what the page renders: an id to build the link from, a label to show, and — when the upstream is
	 * one this server recognises — which mark and wording its own branding requires. Never the credentials.
	 *
	 * `brand` is resolved here rather than in the component, and that is the whole reason this module
	 * exists: the login page renders twice from one props payload, and a value computed during render
	 * would be computed twice and could differ. Resolved once, it travels with the rest.
	 */
	providers: { id: string; displayName: string; brand?: string }[];
}

export async function loginOptionsForBucket(
	bucketId: string
): Promise<LoginOptions> {
	const bucket = await getBucketStore().find(bucketId);
	return {
		// Defaulted true for a bucket that predates the field, which the stores also do on read — belt and
		// braces here because a falsy value would silently close the password door.
		passwordLogin: bucket?.passwordLogin !== false,
		// `=== true` exactly, the mirror of the line above: absent means not required, which is what a
		// bucket predating the field must get, and what makes an unreadable bucket fail open on this
		// rather than locking everyone out of a bucket nobody configured.
		totpRequired: bucket?.totpRequired === true,
		/*
		 * Recognition keys on the stored issuer, never on how the provider came to be configured — nothing
		 * records that, deliberately. So a Google provider somebody typed in by hand long before the
		 * catalogue existed renders with its mark on the next page load, and no migration is owed.
		 */
		providers: orderedForDisplay(enabledProviders(bucket)).map((provider) => {
			const known = knownProviderByIssuer(provider.issuer);
			return {
				id: provider.id,
				displayName: provider.displayName,
				...(known ? { brand: known.catalogueId } : {})
			};
		})
	};
}

/*
 * The order the buttons appear in, which must not be the order somebody happened to connect them in.
 *
 * Stored order is the array's order, so it is stable across reloads — but it is *connection* order, which
 * means adding a provider silently rearranges a page end users already know, and two buckets configured
 * the same way in a different sequence look different. Recognised providers therefore take the catalogue's
 * order and arbitrary ones follow, alphabetically so that they too are independent of when they arrived.
 */
function orderedForDisplay<T extends { id: string; issuer: string }>(
	providers: T[]
): T[] {
	const rank = (provider: T): number => {
		const known = knownProviderByIssuer(provider.issuer);
		if (!known) return KNOWN_PROVIDERS.length;
		return KNOWN_PROVIDERS.indexOf(known);
	};
	// Copied before sorting: the array belongs to the bucket document this was read from.
	return [...providers].sort(
		(a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id)
	);
}

/* The same answer, reached from the client that started the interaction — which is the only trustworthy
 * route to a bucket: a bucket id taken from a request would let anyone aim the page at any tenant. */
export async function loginOptionsForClient(
	clientId: string | undefined
): Promise<LoginOptions> {
	return loginOptionsForBucket(await resolveBucketForRequest(clientId));
}
