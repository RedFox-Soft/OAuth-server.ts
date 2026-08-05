import { createRemoteJWKSet } from 'jose';

import { PROVIDER_CACHE_LIMIT } from './consts.js';

/*
 * The upstream provider's signing keys.
 *
 * jose's own RemoteJWKSet supplies the whole caching contract this feature needs, verified against its
 * source rather than assumed: `getKey` reloads when its freshness window (`cacheMaxAge`, 10 minutes by
 * default) has elapsed, and on a `JWKSNoMatchingKey` — an unknown `kid`, i.e. an upstream that rotated on
 * its own schedule — reloads **once** if the cooldown has passed, then retries. Writing that by hand would
 * be reimplementing a documented library behaviour, so this module does exactly one thing jose does not:
 * it bounds how many providers are held.
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

	const created = createRemoteJWKSet(new URL(jwksUri));
	sets.set(jwksUri, created);
	return created;
}
