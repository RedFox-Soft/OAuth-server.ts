import { configuration } from '../configs/application.ts';

/*
 * Whether an application that requires a code from an authenticator app is being reached without one (specs/127).
 * The one answer the login prompt's check and every grant that acts for a person share, so the browser sign-in and
 * the token side cannot drift apart: a refresh token, a device or CIBA result, an assertion or an exchange is held to
 * the same rule a sign-in is.
 *
 * Only the multi-factor context meets it. A federated sign-in never asks for this server's code, and an absent or
 * unknown context — a grant from before contexts were recorded, an outside assertion — is not evidence of one.
 */
export function codeRequiredAndMissing(
	client: { readonly 'signIn.requireCode'?: boolean } | undefined,
	acr: string | undefined
): boolean {
	if (client?.['signIn.requireCode'] !== true) return false;
	return acr !== configuration.acrMap.multi_factor;
}

/*
 * Whether the sign-in for a path behind the proxy that asks for a code (specs/128 research R4) is being reached without
 * one. The proxy's own client writes `acr_values` with the multi-factor value into its request, and for that client
 * alone the request binds: for any other client `acr_values` stays the voluntary request OIDC Core §3.1.2.1 makes it.
 * Binding it here gives nobody anything — the proxy checks the context of the code it is handed whatever the request
 * said, so removing the value only earns a refusal at the proxy's callback.
 */
export function proxyAsksForCode(
	client: { readonly behindProxyBucketId?: string } | undefined,
	acrValues: unknown,
	acr: string | undefined
): boolean {
	if (client?.behindProxyBucketId === undefined) return false;
	if (typeof acrValues !== 'string') return false;
	const multiFactor = configuration.acrMap.multi_factor;
	return acrValues.split(' ').includes(multiFactor) && acr !== multiFactor;
}

/* What a refusal says, at the token endpoint and to an application its sign-in hands back. */
export const REQUIRE_CODE_DESCRIPTION =
	'the application requires a sign-in with a code from an authenticator app';
