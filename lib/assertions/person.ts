import type { User } from '../adapters/types.js';
import { withFallbackAddress } from '../federation/identity/oidc.js';
import { resolveFederatedAccount } from '../federation/resolve.js';
import { InvalidGrant } from '../helpers/errors.js';
import type { VerifiedAssertion } from './verify.js';

/*
 * The end user an authenticated assertion names, found — or created and linked — by exactly the rules a browser
 * sign-in through the same provider follows (specs/108, clarification Q3): the existing link, the provider's
 * directory correlation, its trusted email and domains, its provisioning choice, the project's sign-up limit.
 * One ladder rather than a copy, so a person gets one answer to "who is this" whichever door they arrive by.
 *
 * Two outcomes a browser can carry on from are refusals here, because there is nobody to carry on with: an
 * address that matched an account holding only a password (the browser asks for that password), and an
 * account whose address a project requires verified and that is not (the browser sends a code). CHAIN §2.4.2:
 * a server unable to identify the subject must deny the request.
 */
export async function personNamedBy(
	assertion: VerifiedAssertion
): Promise<User> {
	const { bucket, provider, claims } = assertion;
	const resolution = await resolveFederatedAccount({
		bucket,
		provider,
		subject: String(claims.sub),
		claims: withFallbackAddress(provider, claims)
	});
	if (!resolution.ok) {
		throw new InvalidGrant(`person:${resolution.reason}`);
	}
	if (bucket.emailVerificationRequired && !resolution.account.verified) {
		throw new InvalidGrant('person:unverified');
	}
	return resolution.account;
}
