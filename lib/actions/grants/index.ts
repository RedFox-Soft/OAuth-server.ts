import { t } from 'elysia';
import { UnsupportedGrantType } from 'lib/helpers/errors.js';
import { provider } from 'lib/provider.js';
import { TokenResponse } from 'lib/shared/response_schemas.js';

// Body every grant handler resolves to (RFC 6749 §5.1), varying by grant_type — see TokenResponse.
type TokenResponseBody = (typeof TokenResponse)['static'];

export const codeGrantParameters = t.Object({
	code: t.String(),
	redirect_uri: t.Optional(t.String()),
	code_verifier: t.String({ pattern: '^[A-Za-z0-9_-]{43}$' })
});

export const refreshTokenGrantParameters = t.Object({
	refresh_token: t.String()
});

export const deviceCodeGrantParameters = t.Object({
	device_code: t.String()
});

export const cibaGrantParameters = t.Object({
	auth_req_id: t.String()
});

export * as authorization_code from './authorization_code.ts';
export * as refresh_token from './refresh_token.ts';
export * as 'urn:ietf:params:oauth:grant-type:device_code' from './device_code.ts';
export * as 'urn:openid:params:grant-type:ciba' from './ciba.ts';

import * as authorization_code from './authorization_code.ts';
import { clientCredentials } from './client_credentials.ts';
import * as refresh_token from './refresh_token.ts';
import * as device_code from './device_code.ts';
import * as ciba from './ciba.ts';
import { ApplicationConfig as config } from 'lib/configs/application.js';

// Grant handlers always resolve to the grant-dependent token response body. No handler returns a
// raw `Response`; the /token route relies on this so its `response` schema is TokenResponse.
type GrantHandler = (oidc: unknown, dPoP: unknown) => Promise<TokenResponseBody>;

export const grantStore: Map<string, GrantHandler> = new Map([
	['authorization_code', authorization_code.handler],
	['client_credentials', clientCredentials],
	['refresh_token', refresh_token.handler],
	['urn:ietf:params:oauth:grant-type:device_code', device_code.handler],
	['urn:openid:params:grant-type:ciba', ciba.handler]
]);

// Single source of truth for the grant types the /token endpoint accepts. An explicit tuple of
// literals (not `keys().map(t.Literal)`, whose array shape collapses the TypeBox static type to
// `never`) so `GrantType` is a real literal union and the /token handler stays well-typed.
export const grantTypeSchema = t.Union(
	[
		t.Literal('authorization_code'),
		t.Literal('client_credentials'),
		t.Literal('refresh_token'),
		t.Literal('urn:ietf:params:oauth:grant-type:device_code'),
		t.Literal('urn:openid:params:grant-type:ciba')
	],
	{ error: 'invalid grant_type' }
);

export type GrantType = (typeof grantTypeSchema)['static'];

// Server-level feature flag gating each optional grant. Mirrors deriveGrantTypes in
// lib/configs/discoverySupport.ts so token dispatch and discovery advertise the same set.
const grantFeatureFlags = {
	client_credentials: 'clientCredentials.enabled',
	'urn:ietf:params:oauth:grant-type:device_code': 'deviceFlow.enabled',
	'urn:openid:params:grant-type:ciba': 'ciba.enabled'
} as const;

export function hasGrant(grantType: string): boolean {
	const flag = grantFeatureFlags[grantType as keyof typeof grantFeatureFlags];
	if (flag && !config[flag]) {
		return false;
	}

	return grantStore.has(grantType);
}

export async function executeGrant(
	grantType: string,
	oidc,
	dPoP
): Promise<TokenResponseBody> {
	const grant = grantStore.get(grantType);
	if (!hasGrant(grantType)) {
		throw new UnsupportedGrantType();
	}
	const res: TokenResponseBody = await grant(oidc, dPoP);
	// event payload kept `{ oidc }`-shaped (was the `ctx` wrapper)
	provider.emit('grant.success', { oidc });
	return res;
}
