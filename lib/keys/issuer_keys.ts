import KeyStore from '../helpers/keystore.js';
import {
	loadKeys as mirrorRootKeys,
	toPublicJwk,
	type PublicJWK
} from '../configs/keystore.js';
import { getBucketKeysStore } from '../adapters/index.js';
import { isAddressable } from '../admin/auth/bucketAddress.js';
import { generateJWKS } from '../helpers/jwks.js';
import type { BucketKey } from '../adapters/types.js';
import type { RequestBucket } from '../configs/issuer.js';
import { ROOT_KEY_OWNER } from '../consts/key_owner.js';

/*
 * The keys each issuer signs, verifies and decrypts with.
 *
 * An addressable bucket is its own issuer and has keys of its own, so a token one bucket mints fails
 * signature verification at a resource server trusting another's — tenant separation no longer rests
 * on every third-party resource server checking `iss`. Everything served at the root — the default
 * bucket, the administrators bucket, a bucket with no address — shares the root issuer and its one key
 * set, stored under `ROOT_KEY_OWNER` beside the buckets' and following the same lifecycle, because
 * giving one issuer two key sets would publish keys some of its own tokens do not verify against.
 *
 * Kept out of `configs/keystore.ts`, which must stay a leaf: this module reaches the adapters, and an
 * await inside the model import graph reorders module evaluation (wiki: model-graph-import-order).
 *
 * A bucket's set is cached per instance for `KEY_CACHE_SECONDS` and dropped at once on this instance's
 * own writes. There is no cross-instance messaging in this server for anything, so a TTL is what bounds
 * how long another instance can lag; the rotation rules in lib/admin/bucket_keys/ are written against
 * it — a key is published for longer than the TTL before it may sign — so the lag never lets one
 * instance sign with a key another does not yet serve.
 */
export const KEY_CACHE_SECONDS = 30;

/* Published this long before it may be promoted: twice the cache, so every instance has reloaded. */
export const KEY_PUBLICATION_SECONDS = 2 * KEY_CACHE_SECONDS;

/*
 * How long a retired key stays published. The longest lifetime a signed artefact can carry: a declared
 * resource's access tokens are capped at a day (`accessTokenTTL`, lib/admin/resources/schema.ts), and
 * ID, logout, userinfo, introspection and authorization responses live an hour or less.
 */
export const RETIRED_KEY_LIFETIME_SECONDS = 24 * 60 * 60;

export interface IssuerKeys {
	readonly signing: KeyStore;
	readonly verification: KeyStore;
	readonly decryption: KeyStore;
	readonly publicJWKS: { keys: PublicJWK[] };
	/* The algorithms this issuer signs and decrypts with. */
	readonly signingAlgorithms: readonly string[] | undefined;
	readonly encryptionAlgorithms: readonly string[] | undefined;
}

export { ROOT_KEY_OWNER };

const cache = new Map<string, { keys: IssuerKeys; loadedAt: number }>();

export function invalidateBucketKeys(bucketId: string): void {
	cache.delete(bucketId);
}

export function invalidateRootKeys(): void {
	cache.delete(ROOT_KEY_OWNER);
}

export function retiredKeyRemovableAt(key: BucketKey): Date {
	return new Date(
		key.stateChangedAt.getTime() + RETIRED_KEY_LIFETIME_SECONDS * 1000
	);
}

function stillPublished(key: BucketKey, now: number): boolean {
	return key.state !== 'retired' || now < retiredKeyRemovableAt(key).getTime();
}

function storeOf(keys: readonly BucketKey[]): KeyStore {
	// Cloned: a KeyStore hands its members out, and the record must stay what the store returned.
	return new KeyStore(keys.map((key) => structuredClone(key.jwk)));
}

function assemble(records: readonly BucketKey[], now: number): IssuerKeys {
	const published = records.filter((key) => stillPublished(key, now));
	const signing = published.filter(
		(key) => key.use === 'sig' && key.state === 'signing'
	);
	const decrypting = published.filter((key) => key.use === 'enc');
	return {
		signing: storeOf(signing),
		verification: storeOf(published.filter((key) => key.use === 'sig')),
		decryption: storeOf(decrypting),
		publicJWKS: { keys: published.map((key) => toPublicJwk(key.jwk)) },
		signingAlgorithms: [...new Set(signing.map((key) => key.alg))],
		encryptionAlgorithms: [...new Set(decrypting.map((key) => key.alg))]
	};
}

/*
 * A bucket's first key, created exactly once however many instances ask at the same moment. The fixed
 * id is the claim: every caller generates a candidate, one insert wins, and the rest discard theirs and
 * read the winner's. RS256, because it is the algorithm every relying party verifies.
 *
 * Called eagerly when a bucket is created with an address or gains one, and lazily by `keysFor` for a
 * bucket that existed before buckets had keys of their own — the switch is immediate, with no period
 * in which the bucket still signs with the root's keys.
 *
 * Not audited on the lazy path, for the reason the root's own first key is not: it is the server
 * provisioning an issuer, not an administrator changing one. The eager calls run inside routes that
 * already record the change that caused them.
 */
export async function ensureBucketKey(bucketId: string): Promise<void> {
	const {
		keys: [jwk]
	} = await generateJWKS('RS256');
	const now = new Date();
	await getBucketKeysStore().createIfAbsent({
		_id: `${bucketId} #initial`,
		bucketId,
		kid: jwk.kid,
		jwk,
		alg: 'RS256',
		use: 'sig',
		state: 'signing',
		createdAt: now,
		stateChangedAt: now
	});
	invalidateBucketKeys(bucketId);
}

/*
 * The root issuer's first key, created exactly once, as a bucket's is. Never at import: the key store is
 * read after the migration gate (lib/index.ts), because a database whose root keys still await migration
 * would otherwise be given a second signer before the gate refused to start on it.
 */
export async function ensureRootKey(): Promise<void> {
	const {
		keys: [jwk]
	} = await generateJWKS('RS256');
	const now = new Date();
	await getBucketKeysStore().createIfAbsent({
		_id: `${ROOT_KEY_OWNER} #initial`,
		bucketId: ROOT_KEY_OWNER,
		kid: jwk.kid,
		jwk,
		alg: 'RS256',
		use: 'sig',
		state: 'signing',
		createdAt: now,
		stateChangedAt: now
	});
	invalidateRootKeys();
}

async function load(ownerId: string, ensure: () => Promise<void>) {
	const now = Date.now();
	const cached = cache.get(ownerId);
	if (cached && now - cached.loadedAt < KEY_CACHE_SECONDS * 1000) {
		return { keys: cached.keys, fresh: false, records: undefined };
	}

	const store = getBucketKeysStore();
	let records = await store.listByBucket(ownerId);
	if (records.length === 0) {
		await ensure();
		records = await store.listByBucket(ownerId);
	}

	const keys = assemble(records, now);
	cache.set(ownerId, { keys, loadedAt: now });
	return { keys, fresh: true, records };
}

/*
 * The root issuer's set, read from its records like any bucket's and cached the same way, so a key
 * promoted or retired on one instance reaches the others within the cache bound — no restart.
 *
 * Each reload mirrors the signing and decryption keys, in place, into `configs/keystore.ts`: that leaf
 * module is what the key-derived algorithm lists (`jwaAlgorithms.ts`) read synchronously, and it may not
 * import this one.
 */
export async function rootKeys(): Promise<IssuerKeys> {
	const { keys, fresh, records } = await load(ROOT_KEY_OWNER, ensureRootKey);
	if (fresh && records) {
		const now = Date.now();
		/*
		 * Signing and decryption keys only, not everything published: the lists derived from the mirror are
		 * what discovery advertises and client registration accepts, and advertising the algorithm of a key
		 * that does not sign yet would let a client register for signatures nothing can produce.
		 */
		mirrorRootKeys(
			records
				.filter(
					(key) =>
						stillPublished(key, now) &&
						(key.use === 'enc' || key.state === 'signing')
				)
				.map((key) => structuredClone(key.jwk))
		);
	}
	return keys;
}

export async function keysFor(bucket: RequestBucket): Promise<IssuerKeys> {
	if (!isAddressable(bucket)) return rootKeys();
	return (await load(bucket._id, () => ensureBucketKey(bucket._id))).keys;
}
