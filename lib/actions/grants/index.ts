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

export * as authorization_code from './authorization_code.ts';
export * as client_credentials from './client_credentials.ts';
export * as refresh_token from './refresh_token.ts';
export * as 'urn:ietf:params:oauth:grant-type:device_code' from './device_code.ts';
export * as 'urn:openid:params:grant-type:ciba' from './ciba.ts';

import * as authorization_code from './authorization_code.ts';
import * as client_credentials from './client_credentials.ts';
import * as refresh_token from './refresh_token.ts';
import * as device_code from './device_code.ts';
import * as ciba from './ciba.ts';

export const grantStore = new Map([
	['authorization_code', authorization_code.handler],
	['client_credentials', client_credentials.handler],
	['refresh_token', refresh_token.handler],
	['urn:ietf:params:oauth:grant-type:device_code', device_code.handler],
	['urn:openid:params:grant-type:ciba', ciba.handler]
]);

if (process.env.NODE_ENV === 'test') {
	grantStore.set('foo', async () => ({ success: true }));
}

export function hasGrant(grantType: string): boolean {
	return grantStore.has(grantType);
}

export async function executeGrant(
	grantType: string,
	ctx,
	dPoP
): Promise<Response | Record<string, unknown>> {
	const grant = grantStore.get(grantType);
	if (!hasGrant(grantType)) {
		throw new UnsupportedGrantType();
	}
	const res: Response | Record<string, unknown> = await grant(ctx, dPoP);
	provider.emit('grant.success', ctx);
	return res;
}
