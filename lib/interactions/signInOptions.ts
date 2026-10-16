import type { UserBucket } from '../adapters/types.js';
import { offeredProviders } from '../federation/offered.js';
import { orderProviders } from '../federation/order.js';
import { knownProviderByIssuer } from '../consts/known_providers.js';
import { selfServiceResetAllowed } from '../password_reset/eligibility.js';

/*
 * What the login page needs to know about a bucket in order to render itself: whether it accepts a password
 * at all, and which providers it offers.
 *
 * One rule, because five places need the same answer and must not disagree — the GET that renders the page,
 * the POST that re-renders it on a bad password, the federation callback that re-renders it on a decline, the
 * doors that refuse when password sign-in is off, and since specs/091 the console's Sign-in tab, which draws
 * the page from an administrator's unsaved switches. A page that offered a password form the POST would
 * refuse, or a preview that showed a button the page does not, is the drift this prevents.
 *
 * That last caller runs in a browser, so this module imports nothing that reaches a store or the
 * configuration: the bucket, its id and the instance's federation switch are arguments. The server reaches it
 * through `loginOptionsForBucket` (./loginOptions.ts), which reads the bucket and supplies the live switch.
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
	 * Whether the page may link to registration and to password reset. Read here, from the bucket the doors
	 * themselves resolve, so the page can never offer a door its own bucket keeps shut — the console's
	 * sign-in page linked to both for as long as the admin bucket refused both.
	 */
	registrationOpen: boolean;
	passwordReset: boolean;
	/*
	 * Only what the page renders: an id to build the link from, a label to show, and — when the upstream is
	 * one this server recognises — which mark and wording its own branding requires. Never the credentials.
	 *
	 * `brand` is resolved here rather than in the component, and that is the whole reason this module
	 * exists: the login page renders twice from one props payload, and a value computed during render
	 * would be computed twice and could differ. Resolved once, it travels with the rest.
	 */
	providers: OfferedProvider[];
}

/*
 * One provider button. `folded` and `subtitle` are decided here with the rest (specs/105), for the reason above:
 * the page, its hydration and the console's preview each read them rather than work them out.
 */
export interface OfferedProvider {
	id: string;
	displayName: string;
	brand?: string;
	/* Under "More sign-in options" rather than in the first list. Present only when true. */
	folded?: true;
	/* The administrator's name, shown under the brand's wording when two providers share one brand. */
	subtitle?: string;
}

/* The fields of a bucket the page depends on, and only those, so the console can pass a draft for a record. */
export type SignInSettings = Pick<
	UserBucket,
	| 'passwordLogin'
	| 'totpRequired'
	| 'registrationOpen'
	| 'federation'
	| 'signInOrder'
>;

export function signInOptionsOf(
	bucketId: string,
	bucket: SignInSettings | null | undefined,
	federationOn: boolean
): LoginOptions {
	return {
		// Defaulted true for a bucket that predates the field, which the stores also do on read — belt and
		// braces here because a falsy value would silently close the password door.
		passwordLogin: bucket?.passwordLogin !== false,
		// `=== true` exactly, the mirror of the line above: absent means not required, which is what a
		// bucket predating the field must get, and what makes an unreadable bucket fail open on this
		// rather than locking everyone out of a bucket nobody configured.
		totpRequired: bucket?.totpRequired === true,
		// A bucket that cannot be read counts as open, exactly as the registration door treats it.
		registrationOpen: bucket?.registrationOpen !== false,
		passwordReset: selfServiceResetAllowed(bucketId, bucket ?? null),
		/*
		 * Recognition keys on the stored issuer, never on how the provider came to be configured — nothing
		 * records that, deliberately. So a Google provider somebody typed in by hand long before the
		 * catalogue existed renders with its mark on the next page load, and no migration is owed.
		 */
		providers: laidOut(
			orderProviders(
				offeredProviders(bucket, federationOn),
				bucket?.signInOrder
			).map((provider) => {
				const known = knownProviderByIssuer(provider.issuer);
				return {
					id: provider.id,
					displayName: provider.displayName,
					...(known ? { brand: known.catalogueId } : {})
				};
			})
		)
	};
}

/*
 * How many buttons a page shows before folding the rest under "More sign-in options" (specs/105).
 *
 * Six all fit a phone's first screen below a password form, so up to six nothing folds; past six the page shows
 * five and folds the rest. A fold of one is never made: it would spend a click to hide a single button.
 */
const ALL_VISIBLE_UP_TO = 6;
const VISIBLE_WHEN_FOLDED = 5;
const FOLD_AT_LEAST = 2;

/*
 * Marks the folded providers and names the ones that share a brand, keeping the administrator's order in both
 * groups.
 *
 * A recognised provider is never folded, even past five: Google's and Apple's branding terms require their button
 * to be no less prominent than any other sign-in option, and a button behind a disclosure is less prominent. The
 * places left go to the other providers in the administrator's order.
 *
 * Two connections to one brand — two Microsoft organisations is the ordinary case — would otherwise be two
 * identical buttons, since the brand fixes the wording; the administrator's name for each becomes its second line.
 */
function laidOut(providers: OfferedProvider[]): OfferedProvider[] {
	const brandCount = new Map<string, number>();
	for (const { brand } of providers)
		if (brand !== undefined)
			brandCount.set(brand, (brandCount.get(brand) ?? 0) + 1);

	let foldedIds = new Set<string>();
	if (providers.length > ALL_VISIBLE_UP_TO) {
		const branded = providers.filter((p) => p.brand !== undefined).length;
		let places = Math.max(0, VISIBLE_WHEN_FOLDED - branded);
		for (const provider of providers) {
			if (provider.brand !== undefined) continue;
			if (places > 0) places--;
			else foldedIds.add(provider.id);
		}
		if (foldedIds.size < FOLD_AT_LEAST) foldedIds = new Set();
	}

	return providers.map((provider) => ({
		...provider,
		...(foldedIds.has(provider.id) ? { folded: true as const } : {}),
		...(provider.brand !== undefined &&
		(brandCount.get(provider.brand) ?? 0) > 1
			? { subtitle: provider.displayName }
			: {})
	}));
}
