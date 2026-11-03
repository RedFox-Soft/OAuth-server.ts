import crypto from 'crypto';

import { issuerFor, type RequestBucket } from '../configs/issuer.js';
import { knownProviderByIssuer } from '../consts/known_providers.js';
import {
	FEDERATION_CALLBACK_PATH,
	MAX_UPSTREAM_DOCUMENT_BYTES,
	UPSTREAM_TIMEOUT_MS
} from './consts.js';
import { guardedFetch, readBounded } from '../shared/egress.js';
import { clientCredential } from './credential.js';
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

/*
 * Whether to bind the authorization code to the request that asked for it.
 *
 * Two sources, and the order is the whole point. **What a provider advertises under-reports what it
 * supports**: of the four recognised entries, three support the binding and only one publishes a challenge
 * method for it — Microsoft recommends it "for all application types, both public and confidential
 * clients" while advertising nothing, and GitHub has supported it since July 2025 while publishing no
 * metadata document at all. Inferring from metadata alone therefore silently dropped the binding from
 * three of the four legs.
 *
 * So a recognised provider's own statement wins, and metadata decides for everything else — which is the
 * only honest rule available for an arbitrary upstream nobody has looked at.
 *
 * The original caution is preserved exactly, and it is why `unknown` sends nothing rather than trying:
 * a provider that rejects a parameter it does not recognise fails sign-in for **all** of its users. A
 * missing binding is a weakness; a rejected authorization request is a total outage.
 */
export function supportsPkce(
	metadata: ProviderMetadata,
	provider?: FederationProvider
): boolean {
	const entry = provider ? knownProviderByIssuer(provider.issuer) : undefined;
	if (entry) return entry.codeBinding === 'S256';
	return metadata.codeChallengeMethods.includes('S256');
}

export function authorizationUrl(
	provider: FederationProvider,
	metadata: ProviderMetadata,
	secrets: { state: string; nonce: string; codeVerifier?: string },
	bucket: RequestBucket,
	/*
	 * A linked sign-in's extra request (specs/120 R4): passed only by the interaction's sign-in start, so a try of a
	 * provider and an unlinked provider ask for exactly what they always did.
	 */
	keep?: { scopes: readonly string[]; params: Readonly<Record<string, string>> }
): string {
	const url = new URL(metadata.authorizationEndpoint);
	const scopes = keep
		? [...new Set([...provider.scopes, ...keep.scopes])]
		: provider.scopes;
	const params = new URLSearchParams({
		...(keep?.params ?? {}),
		client_id: provider.clientId,
		response_type: 'code',
		redirect_uri: callbackUri(bucket),
		scope: scopes.join(' '),
		state: secrets.state,
		nonce: secrets.nonce
	});

	/*
	 * Sent only where an entry asks for it, because it is a demand rather than a preference: one recognised
	 * provider **refuses the authorization request outright** unless the return is posted back, whenever a
	 * name or an address is among the scopes. Left unset otherwise, so every other upstream keeps its own
	 * default and no provider is told about a mode it never advertised.
	 */
	const entry = knownProviderByIssuer(provider.issuer);
	if (entry && entry.returnMode !== 'query') {
		params.set('response_mode', entry.returnMode);
	}

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
	/*
	 * The OAuth `error` and Microsoft's `suberror` of a 400 answer, when it had them: a linked sign-in refused for
	 * its extra scopes is told apart by these (specs/120 R10). Codes only, never the description.
	 */
	readonly upstream?: { error?: string; suberror?: string };

	constructor(
		reason: ExchangeFailure,
		detail?: string,
		upstream?: { error?: string; suberror?: string }
	) {
		super(`code exchange failed: ${reason}${detail ? ` (${detail})` : ''}`);
		this.reason = reason;
		if (upstream) this.upstream = upstream;
	}
}

function errorCodesOf(text: string): { error?: string; suberror?: string } {
	try {
		const parsed: unknown = JSON.parse(text);
		if (typeof parsed !== 'object' || parsed === null) return {};
		const { error, suberror } = parsed as Record<string, unknown>;
		return {
			...(typeof error === 'string' ? { error } : {}),
			...(typeof suberror === 'string' ? { suberror } : {})
		};
	} catch {
		return {};
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
 * Returns the `id_token` and the whole answer. The identity layer hands the answer on only for a sign-in linked to a
 * connected service (specs/120), whose tokens the vault then keeps sealed; for every other sign-in the access and
 * refresh tokens go no further than the identity layer, as before.
 */
export async function exchangeCode(
	provider: FederationProvider,
	metadata: ProviderMetadata,
	code: string,
	bucket: RequestBucket,
	codeVerifier?: string
): Promise<{ idToken: string | undefined; response: Record<string, unknown> }> {
	const method = authMethod(metadata);
	/*
	 * Resolved rather than read off the provider, because one recognised upstream issues no secret and
	 * derives its credential from a stored key instead. Everything below is unchanged by that: whatever the
	 * model, what arrives here is the one string the endpoint expects.
	 */
	const credential = await clientCredential(provider);

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
		body.set('client_secret', credential);
	}

	const headers: Record<string, string> = {
		'content-type': 'application/x-www-form-urlencoded'
	};
	if (method === 'basic') {
		// RFC 6749 §2.3.1: both halves are form-urlencoded before being joined and base64'd.
		const credentials = `${encodeURIComponent(provider.clientId)}:${encodeURIComponent(credential)}`;
		headers.authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
	}

	/*
	 * Through the egress boundary: the endpoint comes from a discovery document a group member's issuer
	 * serves, and this request carries the provider's client credential. A redirect answering a POST is
	 * returned unfollowed and refused as a non-success below.
	 */
	let text: string;
	try {
		const response = await guardedFetch(metadata.tokenEndpoint, {
			method: 'POST',
			headers,
			body,
			timeoutMs: UPSTREAM_TIMEOUT_MS
		});
		if (!response.ok) {
			throw new ExchangeError(
				'unreachable',
				`status ${response.status}`,
				response.status === 400
					? errorCodesOf(
							await readBounded(response, MAX_UPSTREAM_DOCUMENT_BYTES)
						)
					: undefined
			);
		}
		text = await readBounded(response, MAX_UPSTREAM_DOCUMENT_BYTES);
	} catch (err) {
		if (err instanceof ExchangeError) throw err;
		throw new ExchangeError(
			'unreachable',
			err instanceof Error ? err.message : undefined
		);
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new ExchangeError('malformed', 'body is not JSON');
	}
	if (typeof parsed !== 'object' || parsed === null) {
		throw new ExchangeError('malformed', 'not an object');
	}

	const answer = parsed as Record<string, unknown>;
	const idToken = answer.id_token;
	return {
		idToken: typeof idToken === 'string' ? idToken : undefined,
		response: answer
	};
}
