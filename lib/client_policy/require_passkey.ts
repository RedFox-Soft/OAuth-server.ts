import { configuration } from '../configs/application.ts';
import { meets } from '../helpers/acr_satisfaction.ts';

/*
 * Whether an application that requires a passkey (specs/142) is being reached without a sign-in that reached the
 * phishing-resistant context. The one answer the login prompt and every grant that acts for a person share, as
 * `codeRequiredAndMissing` is for a code, and checked before it: a passkey requirement includes the code one.
 *
 * Callers hand the context the sign-in reached (`reachedAcr`), never the value reported to the application. A grant no
 * browser sign-in here made — a device code, a back-channel request, an assertion, an exchanged token — never reached
 * it (research R4, R5), so it is refused; so is an absent or unknown context.
 */
export function passkeyRequiredAndMissing(
	client: { readonly 'signIn.requirePasskey'?: boolean } | undefined,
	acr: string | undefined
): boolean {
	if (client?.['signIn.requirePasskey'] !== true) return false;
	return !meets(acr, 'phishing_resistant');
}

/*
 * Whether the sign-in for a path behind the proxy that asks for a passkey (specs/143 research R4) is being reached
 * without one. Mirrors `proxyAsksForCode`: binds only for the project's proxy client, and the proxy callback checks
 * the redeemed code whatever the request said.
 */
export function proxyAsksForPasskey(
	client: { readonly behindProxyBucketId?: string } | undefined,
	acrValues: unknown,
	acr: string | undefined
): boolean {
	if (client?.behindProxyBucketId === undefined) return false;
	if (typeof acrValues !== 'string') return false;
	return (
		acrValues.split(' ').includes(configuration.acrMap.phishing_resistant) &&
		!meets(acr, 'phishing_resistant')
	);
}

/* What a refusal says, at the token endpoint and to an application its sign-in hands back. Fixed ASCII. */
export const REQUIRE_PASSKEY_DESCRIPTION =
	'the application requires a passkey sign-in';
