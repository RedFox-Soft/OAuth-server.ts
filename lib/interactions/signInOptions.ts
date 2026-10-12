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
	providers: { id: string; displayName: string; brand?: string }[];
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
		providers: orderProviders(
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
	};
}
