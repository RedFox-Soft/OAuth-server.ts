import { getBucketKeysStore } from 'lib/adapters/index.js';
import type { BucketKey } from 'lib/adapters/types.js';
import { ROOT_KEY_OWNER } from 'lib/consts/key_owner.js';
import { type JWKS } from 'lib/configs/verifyJWKs.js';

/*
 * The root issuer's keys, written the way the server stores them: records under the reserved owner, the
 * first signing key of each algorithm `signing` and every other key `published`. Replaces whatever root
 * keys the store held, so one spec's keys can never leak into the next.
 */
export async function writeRootKeys(keys: readonly JWKS[]): Promise<void> {
	const store = getBucketKeysStore();
	await store.destroyByBucket(ROOT_KEY_OWNER);
	const signers = new Set<string>();
	const now = new Date(Date.now());
	for (const jwk of keys) {
		const use = jwk.use === 'enc' ? 'enc' : 'sig';
		const signs = use === 'sig' && !signers.has(jwk.alg);
		if (signs) signers.add(jwk.alg);
		const record: BucketKey = {
			_id: `${ROOT_KEY_OWNER} ${jwk.kid}`,
			bucketId: ROOT_KEY_OWNER,
			kid: jwk.kid,
			jwk: structuredClone(jwk),
			alg: jwk.alg,
			use,
			state: signs ? 'signing' : 'published',
			createdAt: now,
			stateChangedAt: now
		};
		await store.createIfAbsent(record);
	}
}
