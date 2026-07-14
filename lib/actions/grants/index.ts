import { t } from 'elysia';
import { UnsupportedGrantType } from 'lib/helpers/errors.js';
import { provider } from 'lib/provider.js';

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

export const grantStore = new Map([
	['authorization_code', authorization_code.handler],
	['client_credentials', clientCredentials],
	['refresh_token', refresh_token.handler],
	['urn:ietf:params:oauth:grant-type:device_code', device_code.handler],
	['urn:openid:params:grant-type:ciba', ciba.handler]
]) as const;

if (process.env.NODE_ENV === 'test') {
	grantStore.set('foo', async () => ({ success: true }));
}

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
): Promise<Response | Record<string, unknown>> {
	const grant = grantStore.get(grantType);
	if (!hasGrant(grantType)) {
		throw new UnsupportedGrantType();
	}
	const res: Response | Record<string, unknown> = await grant(oidc, dPoP);
	// event payload kept `{ oidc }`-shaped (was the `ctx` wrapper)
	provider.emit('grant.success', { oidc });
	return res;
}
