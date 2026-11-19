import { configuration } from '../configs/application.ts';
import epochTime from '../helpers/epoch_time.ts';
import { InvalidGrant } from '../helpers/errors.ts';
import type { ResourceSignIn } from '../helpers/resource_server.ts';
import { requirementUnmet, type UnmetRequirement } from './sign_in_rule.ts';

/*
 * Whether a sign-in meets an API's sign-in requirement (specs/130 research R3). The one answer the login prompt, every
 * grant that issues a token for a person and the proxy's check share, so a browser sign-in, a renewal and a presented
 * token cannot be held to three different rules.
 *
 * It judges only the facts of the sign-in itself: the authentication context it reached and when it happened. A
 * renewal carries the sign-in it renews, so it never makes a sign-in recent. A missing or unreadable sign-in time is
 * never recent: `undefined` in the arithmetic would be `NaN`, and every comparison with `NaN` is false, which would
 * read as a pass.
 */

export interface SignInFacts {
	readonly acr: string | null | undefined;
	/* Seconds since the epoch. */
	readonly authTime: number | null | undefined;
}

export type { UnmetRequirement };

/* Whether a sign-in with this authentication context included a code from an authenticator app. */
export function hadCode(acr: string | null | undefined): boolean {
	return acr === configuration.acrMap.multi_factor;
}

export function signInRequirementUnmet(
	signIn: ResourceSignIn | undefined,
	facts: SignInFacts,
	nowSeconds: number
): UnmetRequirement | null {
	return requirementUnmet(
		signIn,
		{ withCode: hadCode(facts.acr), authTime: facts.authTime },
		nowSeconds
	);
}

/*
 * What a refusal says at the token endpoint and to the client a sign-in hands back. Fixed ASCII, no names. "Two-step":
 * a code from an authenticator app, or a passkey where the project accepts them (specs/139 research R22).
 */
export const API_CODE_DESCRIPTION = 'the API requires two-step sign-in';
export const API_RECENT_DESCRIPTION = 'the API requires a more recent sign-in';

/* Assertion grants and client credentials, which carry no sign-in this server saw, for an API with a requirement. */
export const API_PERSON_DESCRIPTION = "the API requires a person's own sign-in";
export const API_MACHINE_DESCRIPTION =
	"this API accepts only tokens from a person's sign-in";

/* The proxy's `error_description` (RFC 6750 §3: printable ASCII without `"` or `\`). */
export const CHALLENGE_CODE_DESCRIPTION = 'two-step sign-in is required';
export const CHALLENGE_RECENT_DESCRIPTION = 'a more recent sign-in is required';

/* One description for a refusal, the code first. */
export function descriptionOf(unmet: UnmetRequirement): string {
	return unmet.code ? API_CODE_DESCRIPTION : API_RECENT_DESCRIPTION;
}

/*
 * The token endpoint's refusal of a token for an API whose requirement the sign-in behind it does not meet (specs/130
 * research R5): `invalid_grant`, since the grant presented cannot produce such a token.
 */
export function assertSignInMeets(
	resourceServer: { readonly signIn?: ResourceSignIn } | undefined,
	facts: SignInFacts
): void {
	const unmet = signInRequirementUnmet(
		resourceServer?.signIn,
		facts,
		epochTime()
	);
	if (unmet) throw new InvalidGrant(descriptionOf(unmet));
}
