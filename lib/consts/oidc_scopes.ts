/*
 * The scopes whose meaning is fixed by OpenID Connect Core §5.4 (and `groups`, which this server defines the
 * same way). The consent page describes them from its own vocabulary, which is why an operator may not
 * describe them in `consent.scopeDescriptions`: a second description would contradict the first on the
 * same page.
 */
export const STANDARD_OIDC_SCOPES = [
	'openid',
	'profile',
	'email',
	'address',
	'phone',
	'offline_access',
	'groups'
] as const;

export type StandardOidcScope = (typeof STANDARD_OIDC_SCOPES)[number];

const STANDARD: ReadonlySet<string> = new Set(STANDARD_OIDC_SCOPES);

export function isStandardOidcScope(scope: string): scope is StandardOidcScope {
	return STANDARD.has(scope);
}
