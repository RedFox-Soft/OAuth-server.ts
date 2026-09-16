import crypto from 'crypto';

import { issuerFor, type RequestBucket } from '../configs/issuer.js';
import { FEDERATION_CALLBACK_PATH } from './consts.js';
import type { ProviderMetadata } from './discovery.js';
import type { FederationProvider } from './types.js';

/*
 * The two outbound legs: where we send the user, and how we exchange the code they come back with.
 *
 * Both read their protocol choices from the provider's published metadata rather than from a setting. The
 * provider already declares what it supports; a knob would only add a way for an operator to contradict it.
 */

/*
 * Fixed for every *interaction*, because an upstream matches `redirect_uri` by exact string. That is
 * why the callback cannot read the interaction cookie — the address cannot carry a `uid`.
 *
 * It is not fixed for every *bucket*, and the distinction took a correction to see. A bucket is
 * configuration, not an interaction: it is constant for any given provider record, so the address
 * stays constant for the upstream that matches it. Each bucket already holds its own upstream client
 * credentials per provider, so a per-bucket callback is one `redirect_uri` per upstream client — the
 * normal arrangement rather than an extra one.
 *
 * The default bucket's issuer is the server's own, so its callback address is unchanged and no
 * existing registration has to be touched.
 */
export function callbackUri(bucket: RequestBucket): string {
	return `${issuerFor(bucket)}${FEDERATION_CALLBACK_PATH}`;
}

/* PKCE only when the provider says S256: sending an unsupported parameter breaks sign-in at providers
 * that reject unknown ones, for a spec-compliant reason. */
export function supportsPkce(metadata: ProviderMetadata): boolean {
	return metadata.codeChallengeMethods.includes('S256');
}

export function authorizationUrl(
	provider: FederationProvider,
	metadata: ProviderMetadata,
	secrets: { state: string; nonce: string; codeVerifier?: string },
	bucket: RequestBucket
): string {
	const url = new URL(metadata.authorizationEndpoint);
	const params = new URLSearchParams({
		client_id: provider.clientId,
		response_type: 'code',
		redirect_uri: callbackUri(bucket),
		scope: provider.scopes.join(' '),
		state: secrets.state,
		nonce: secrets.nonce
	});

	if (secrets.codeVerifier) {
		params.set(
			'code_challenge',
			crypto
				.createHash('sha256')
				.update(secrets.codeVerifier)
				.digest('base64url')
		);
		params.set('code_challenge_method', 'S256');
	}

	/*
	 * Merged rather than replaced: a provider is entitled to carry its own query on the authorization
	 * endpoint (a tenant or a policy identifier), and overwriting the URL's search would silently drop it.
	 */
	for (const [key, value] of params) {
		url.searchParams.set(key, value);
	}
	return url.toString();
}

export type ExchangeFailure = 'unsupported_auth' | 'unreachable' | 'malformed';

export class ExchangeError extends Error {
	readonly reason: ExchangeFailure;

	constructor(reason: ExchangeFailure, detail?: string) {
		super(`code exchange failed: ${reason}${detail ? ` (${detail})` : ''}`);
		this.reason = reason;
	}
}

/*
 * Preferring basic over post is the RFC 6749 §2.3.1 recommendation, and neither advertised means the
 * provider authenticates its clients some way this server does not implement — refused as unusable rather
 * than attempted blind, which would leak the secret into a request shape the provider did not ask for.
 */
function authMethod(metadata: ProviderMetadata): 'basic' | 'post' {
	if (metadata.tokenAuthMethods.includes('client_secret_basic')) return 'basic';
	if (metadata.tokenAuthMethods.includes('client_secret_post')) return 'post';
	throw new ExchangeError('unsupported_auth', metadata.tokenAuthMethods.join());
}

/*
 * Exchange the code for an identity assertion.
 *
 * Returns the `id_token` and **nothing else**. The provider's access and refresh tokens are destructured
 * away here and never bound to a name that outlives this function: no feature calls an upstream API, so
 * keeping them would create a secret to leak and a refresh lifecycle to maintain.
 */
export async function exchangeCode(
	provider: FederationProvider,
	metadata: ProviderMetadata,
	code: string,
	bucket: RequestBucket,
	codeVerifier?: string
): Promise<string | undefined> {
	const method = authMethod(metadata);

	const body = new URLSearchParams({
		grant_type: 'authorization_code',
		code,
		redirect_uri: callbackUri(bucket),
		client_id: provider.clientId
	});
	if (codeVerifier) {
		body.set('code_verifier', codeVerifier);
	}
	if (method === 'post') {
		body.set('client_secret', provider.clientSecret);
	}

	const headers: Record<string, string> = {
		'content-type': 'application/x-www-form-urlencoded'
	};
	if (method === 'basic') {
		// RFC 6749 §2.3.1: both halves are form-urlencoded before being joined and base64'd.
		const credentials = `${encodeURIComponent(provider.clientId)}:${encodeURIComponent(provider.clientSecret)}`;
		headers.authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
	}

	let response: Response;
	try {
		response = await fetch(metadata.tokenEndpoint, {
			method: 'POST',
			headers,
			body
		});
	} catch (err) {
		throw new ExchangeError(
			'unreachable',
			err instanceof Error ? err.message : undefined
		);
	}

	if (!response.ok) {
		throw new ExchangeError('unreachable', `status ${response.status}`);
	}

	let parsed: unknown;
	try {
		parsed = await response.json();
	} catch {
		throw new ExchangeError('malformed', 'body is not JSON');
	}
	if (typeof parsed !== 'object' || parsed === null) {
		throw new ExchangeError('malformed', 'not an object');
	}

	const idToken = (parsed as Record<string, unknown>).id_token;
	return typeof idToken === 'string' ? idToken : undefined;
}
