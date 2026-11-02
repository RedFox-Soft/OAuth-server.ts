import type { ResolvedService } from './catalogue.js';
import type { ConnectSecrets } from './state.js';

/*
 * The provider address a connect flow sends the person to (specs/117 contracts/account-page.md step 4).
 *
 * Never a `response_mode`, and never the sign-in catalogue's `returnMode`: the flow is bound to the person's
 * session cookie, which is `SameSite=Lax` and reaches this server only on a top-level GET, so a provider
 * posting the answer back (`form_post`) would arrive without it and every connect would be refused.
 */
export function authorizationRedirect(
	service: ResolvedService,
	clientId: string,
	redirectUri: string,
	scopes: readonly string[],
	secrets: ConnectSecrets
): string {
	const url = new URL(service.authorizationEndpoint);
	const asked = [...new Set([...service.alwaysScopes, ...scopes])];
	url.searchParams.set('response_type', 'code');
	url.searchParams.set('client_id', clientId);
	url.searchParams.set('redirect_uri', redirectUri);
	if (asked.length > 0) {
		url.searchParams.set(
			service.scopeParam,
			asked.join(service.scopeSeparator)
		);
	}
	url.searchParams.set('state', secrets.state);
	if (secrets.nonce) url.searchParams.set('nonce', secrets.nonce);
	if (secrets.codeChallenge) {
		url.searchParams.set('code_challenge', secrets.codeChallenge);
		url.searchParams.set('code_challenge_method', 'S256');
	}
	for (const [name, value] of Object.entries(
		service.extraAuthorizationParams
	)) {
		url.searchParams.set(name, value);
	}
	return url.href;
}

/* What the service asks for now, as the flow records it: the administrator's scopes plus the always-added ones. */
export function requestedScopes(
	service: ResolvedService,
	scopes: readonly string[]
): string[] {
	return [...new Set([...service.alwaysScopes, ...scopes])];
}
