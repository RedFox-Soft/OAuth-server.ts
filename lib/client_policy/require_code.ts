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

/* What a refusal says, at the token endpoint and to an application its sign-in hands back. */
export const REQUIRE_CODE_DESCRIPTION =
	'the application requires a sign-in with a code from an authenticator app';
