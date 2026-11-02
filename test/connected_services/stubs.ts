import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import { mock } from '../fetch_mock.js';
import { forgetDiscovery } from 'lib/federation/discovery.js';

/*
 * Providers a person connects an account at (specs/117), over the outbound-fetch mock. Each registers exactly
 * the interceptors a case consumes, single-use, so an unhit one fails the case that registered it
 * (test/federation/idp_stub.ts states the rule). Every token value is distinctive, so a case can search a
 * datastore copy or an event for it.
 */

const ALG = 'RS256';
const json = { headers: { 'content-type': 'application/json' } };

let counter = 0;
export function unique(prefix: string): string {
	counter += 1;
	return `${prefix}-${String(counter)}-${Math.random().toString(36).slice(2, 8)}`;
}

export interface Recorded {
	body: string;
}

/* The answers a token endpoint gives, by provider shape. */
export function githubTokens(
	options: { refresh?: boolean; scope?: string } = {}
) {
	return {
		access_token: unique('gho_access'),
		token_type: 'bearer',
		scope: options.scope ?? 'read:user',
		...(options.refresh === false
			? {}
			: {
					refresh_token: unique('ghr_refresh'),
					expires_in: 28800,
					refresh_token_expires_in: 15897600
				})
	};
}

export function githubStub() {
	const login = mock('https://github.com');
	const api = mock('https://api.github.com');
	return {
		expectToken(
			body: Record<string, unknown>,
			check?: (form: string) => boolean
		) {
			login
				.intercept({
					path: '/login/oauth/access_token',
					method: 'POST',
					...(check ? { body: check } : {})
				})
				.reply(200, JSON.stringify(body), json);
		},
		expectTokenFailure(status: number) {
			login
				.intercept({ path: '/login/oauth/access_token', method: 'POST' })
				.reply(
					status,
					JSON.stringify({ error: 'bad_verification_code' }),
					json
				);
		},
		expectUser(profile: Record<string, unknown>, status = 200) {
			api
				.intercept({ path: '/user' })
				.reply(status, JSON.stringify(profile), json);
		},
		expectRevoke(
			clientId: string,
			status = 204,
			check?: (body: string) => boolean
		) {
			api
				.intercept({
					path: `/applications/${clientId}/grant`,
					method: 'DELETE',
					...(check ? { body: check } : {})
				})
				.reply(status, '');
		}
	};
}

export function slackStub() {
	const slack = mock('https://slack.com');
	return {
		expectToken(
			body: Record<string, unknown>,
			check?: (form: string) => boolean
		) {
			slack
				.intercept({
					path: '/api/oauth.v2.access',
					method: 'POST',
					...(check ? { body: check } : {})
				})
				.reply(200, JSON.stringify(body), json);
		},
		expectRevoke(ok = true) {
			slack
				.intercept({ path: '/api/auth.revoke', method: 'POST' })
				.reply(200, JSON.stringify({ ok, revoked: ok }), json);
		}
	};
}

export function slackTokens(team = 'T0001', user = 'U0001') {
	return {
		ok: true,
		app_id: 'A0001',
		team: { id: team, name: 'Acme Workspace' },
		enterprise: null,
		authed_user: {
			id: user,
			scope: 'users:read,chat:write',
			access_token: unique('xoxp-access'),
			token_type: 'user'
		}
	};
}

/*
 * An OpenID Connect provider at an origin of its own: discovery, keys, token, revocation. The ID token echoes the
 * nonce of the authorization request, which does not exist until the flow has started, so the token answer is
 * registered from the provider address the server redirected to.
 */
export async function oidcStub(
	origin: string,
	options: {
		clientId: string;
		issParameterSupported?: boolean;
		revocation?: boolean;
		issuerPath?: string;
	}
) {
	const issuer = `${origin}${options.issuerPath ?? ''}`;
	forgetDiscovery(issuer);
	const keyPair = await generateKeyPair(ALG, { extractable: true });
	const tag = unique('k');
	const target = mock(origin);
	const base = options.issuerPath ?? '';
	const metadata = {
		issuer,
		authorization_endpoint: `${issuer}/authorize`,
		token_endpoint: `${issuer}/token`,
		jwks_uri: `${issuer}/jwks?${tag}`,
		response_types_supported: ['code'],
		subject_types_supported: ['public'],
		id_token_signing_alg_values_supported: [ALG],
		code_challenge_methods_supported: ['S256'],
		token_endpoint_auth_methods_supported: ['client_secret_basic'],
		...(options.issParameterSupported
			? { authorization_response_iss_parameter_supported: true }
			: {}),
		...(options.revocation ? { revocation_endpoint: `${issuer}/revoke` } : {})
	};
	return {
		issuer,
		expectDiscovery() {
			target
				.intercept({ path: `${base}/.well-known/openid-configuration` })
				.reply(200, JSON.stringify(metadata), json);
		},
		async answerToken(
			authorizeUrl: URL,
			claims: Record<string, unknown>,
			tokens: Record<string, unknown>,
			check?: (form: string) => boolean
		) {
			const jwk = await exportJWK(keyPair.publicKey);
			target.intercept({ path: `${base}/jwks?${tag}` }).reply(
				200,
				JSON.stringify({
					keys: [{ ...jwk, alg: ALG, use: 'sig', kid: tag }]
				}),
				json
			);
			const now = Math.floor(Date.now() / 1000);
			const idToken = await new SignJWT({
				iss: issuer,
				aud: options.clientId,
				sub: 'upstream-subject',
				nonce: authorizeUrl.searchParams.get('nonce'),
				iat: now,
				...claims
			})
				.setProtectedHeader({ alg: ALG, kid: tag })
				.setExpirationTime(now + 300)
				.sign(keyPair.privateKey);
			target
				.intercept({
					path: `${base}/token`,
					method: 'POST',
					...(check ? { body: check } : {})
				})
				.reply(200, JSON.stringify({ ...tokens, id_token: idToken }), json);
		},
		expectRevoke(check?: (form: string) => boolean, status = 200) {
			target
				.intercept({
					path: `${base}/revoke`,
					method: 'POST',
					...(check ? { body: check } : {})
				})
				.reply(status, '');
		}
	};
}
