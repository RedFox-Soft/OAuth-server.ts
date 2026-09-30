import { createRemoteJWKSet, customFetch } from 'jose';

import {
	MAX_UPSTREAM_DOCUMENT_BYTES,
	PROVIDER_CACHE_LIMIT,
	UPSTREAM_TIMEOUT_MS
} from './consts.js';
import { guardedFetch, readBounded } from '../shared/egress.js';

/*
 * The upstream provider's signing keys.
 *
 * jose's own RemoteJWKSet supplies the caching, verified against its source rather than assumed: `getKey`
 * reloads when its freshness window (`cacheMaxAge`, 10 minutes by default) has elapsed, and on a
 * `JWKSNoMatchingKey` — an unknown `kid`, i.e. an upstream that rotated on its own schedule — reloads
 * **once** unless the cooldown is running, then retries. The cooldown is switched off: its default of 30
 * seconds refused every sign-in in the half-minute after a rotation (the conformance suite's
 * `signing-key-rotation` module found it), and it defends against nothing here — the token is read from the
 * provider's own token endpoint, so only the provider can present an unknown `kid`. A rotation to a key with
 * *no* `kid` never raises `JWKSNoMatchingKey` at all; verifyIdToken.ts handles that one. Beyond those, this
 * module does one thing jose does not: it bounds how many providers are held.
 *
 * The bound matters because the URL is read from a bucket document an operator edits. jose holds one
 * instance per URL and knows nothing about how many URLs exist.
 *
 * lib/helpers/jwt.ts is deliberately not extended for this: it takes *this server's* keystore object
 * (selectForVerify / getKeyObject / refresh), so adapting an upstream key set to that shape would mean
 * writing a second keystore implementation to reach a verifier jose already exposes.
 */

type RemoteKeySet = ReturnType<typeof createRemoteJWKSet>;

const sets = new Map<string, RemoteKeySet>();

export function keySetFor(jwksUri: string): RemoteKeySet {
	const existing = sets.get(jwksUri);
	if (existing) {
		return existing;
	}

	if (sets.size >= PROVIDER_CACHE_LIMIT) {
		// Insertion-ordered: the oldest entry is the provider longest without a sign-in.
		const oldest = sets.keys().next().value;
		if (oldest !== undefined) sets.delete(oldest);
	}

	const created = createRemoteJWKSet(new URL(jwksUri), {
		cooldownDuration: 0,
		[customFetch]: fetchThroughBoundary
	});
	sets.set(jwksUri, created);
	return created;
}

/*
 * jose's own fetch already refuses redirects and times out; it does not know which addresses this server
 * must not reach or how large a body it will hold. The URL comes from a discovery document a group
 * member's issuer serves, so it goes through the egress boundary like every other upstream request. jose
 * still gets a Response it can read as it would its own — the body re-wrapped once it has been bounded.
 */
async function fetchThroughBoundary(
	url: string,
	options: { headers: Headers }
): Promise<Response> {
	const response = await guardedFetch(url, {
		headers: Object.fromEntries(options.headers),
		timeoutMs: UPSTREAM_TIMEOUT_MS,
		maxRedirects: 0
	});
	return new Response(
		await readBounded(response, MAX_UPSTREAM_DOCUMENT_BYTES),
		{ status: response.status, headers: response.headers }
	);
}
