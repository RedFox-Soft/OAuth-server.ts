import { t } from 'elysia';

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
