import crypto from 'node:crypto';
import QuickLRU from 'quick-lru';

import { getBucketStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';

/*
 * A project's proxy key (specs/124 research R5): what the operator's proxy sends with each check to show it runs a
 * recipe of this feature — one that also overwrites `X-Forwarded-For` with the connection's address. The key proves
 * the recipe, not the address; the address is believed because that recipe writes it.
 *
 * At most two are active, so one can replace the other without a moment when the proxy's key is refused. Only a
 * digest is stored: the server compares, and never needs the key back.
 */

export const PROXY_KEY_HEADER = 'x-foxauth-proxy-key';
export const MAX_PROXY_KEYS = 2;

const KEY_PREFIX = 'fpk_';

export function digestOfKey(key: string): string {
	return crypto.createHash('sha256').update(key).digest('base64url');
}

export function newProxyKey(): {
	id: string;
	key: string;
	digest: string;
} {
	const key = `${KEY_PREFIX}${crypto.randomBytes(32).toString('base64url')}`;
	return {
		id: crypto.randomBytes(9).toString('base64url'),
		key,
		digest: digestOfKey(key)
	};
}

export interface KeyMatch {
	present: boolean;
	valid: boolean;
}

/*
 * Whether the presented value is one of the project's active keys. The digests are compared in constant time and
 * every one is compared, so how long the answer takes says nothing about which key, or how much of one, matched.
 */
export function matchProxyKey(
	bucket: Pick<UserBucket, 'proxyKeys'>,
	presented: string | null
): KeyMatch {
	if (presented === null || presented === '') {
		return { present: false, valid: false };
	}
	const candidate = Buffer.from(digestOfKey(presented));
	let valid = false;
	for (const stored of bucket.proxyKeys ?? []) {
		const known = Buffer.from(stored.digest);
		if (
			known.length === candidate.length &&
			crypto.timingSafeEqual(known, candidate)
		) {
			valid = true;
		}
	}
	return { present: true, valid };
}

/*
 * A project's keys for the checks, read only when a check presents a key, and kept half a minute: every page asset is
 * a check, and keys change by an administrator's hand. A withdrawal is seen at once on the server that made it
 * (`forgetProxyKeys`) and within half a minute on the others.
 */
const KEYS_MS = 30_000;
const cached = new QuickLRU<string, Pick<UserBucket, 'proxyKeys'>>({
	maxSize: 10_000,
	maxAge: KEYS_MS
});

export async function proxyKeysOf(
	bucketId: string
): Promise<Pick<UserBucket, 'proxyKeys'>> {
	const hit = cached.get(bucketId);
	if (hit) return hit;
	const bucket = await getBucketStore().find(bucketId);
	const keys = { proxyKeys: bucket?.proxyKeys ?? [] };
	cached.set(bucketId, keys);
	return keys;
}

export function forgetProxyKeys(bucketId: string): void {
	cached.delete(bucketId);
}
