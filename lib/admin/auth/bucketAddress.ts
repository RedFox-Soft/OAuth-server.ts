import { getBucketStore } from '../../adapters/index.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../consts.js';
import type { UserBucket } from '../../adapters/types.js';
import { UnknownBucket } from '../../helpers/errors.js';
import {
	DEFAULT_REQUEST_BUCKET,
	type RequestBucket
} from '../../configs/issuer.js';

/*
 * Which bucket a request is addressed to, from the address itself.
 *
 * This is not `resolveBucketForRequest`, and the two answer different questions. That one asks which
 * bucket a *client* belongs to — it is how a client that names no bucket is placed, and it still
 * decides where a dynamically registered client lands. This one reads the address: the first path
 * segment names a bucket, or there is no segment and the request is the default bucket's.
 *
 * The address is authoritative for the request, and the client is then checked against it. Doing it
 * the other way round would let a client parameter move a request between populations, which is
 * exactly what the rules in `resolveBucket.ts` were written to prevent.
 */

/*
 * A slug resolves to the same bucket for as long as that bucket exists. That is not a convention this
 * cache hopes for — `UserBucket.slug` is `readonly`, the admin update body has no such field, and the
 * store's `update` patch cannot carry one; the single writer that reaches an existing record is the
 * provisioning repair, which writes only where there is nothing to overwrite. So the only events this
 * cache has to survive are a bucket appearing and a bucket going away, and both call
 * `forgetBucketAddresses`.
 *
 * Cached because this is read on every request that carries a prefix, and the alternative is a
 * datastore round trip per request to answer a question whose answer almost never changes. Positive
 * entries only — a miss stays a miss, so a bucket created a moment ago is not locked out by a cached
 * negative.
 */
const bySlug = new Map<string, UserBucket>();
const byId = new Map<string, RequestBucket>();

/*
 * Whether a bucket has an address of its own.
 *
 * Two kinds do not. A bucket with no slug has nothing to be addressed by — its clients use the bare
 * endpoints, which is what they did before buckets became tenants. And the two **reserved** buckets
 * are served at the root by design: the default bucket is the instance's own population, and the
 * administrators bucket is what the admin console authenticates against as a relying party on the
 * instance's issuer. Both carry a slug regardless, because a session cookie has to be named after
 * something and an empty name is not a name.
 *
 * Admitting either at a prefixed address would give one population two issuer identifiers, which is
 * the one thing an issuer identifier may not have.
 */
export function isAddressable(bucket: { _id: string; slug?: string }): boolean {
	if (!bucket.slug) return false;
	return bucket._id !== DEFAULT_BUCKET_ID && bucket._id !== ADMIN_BUCKET_ID;
}

export function forgetBucketAddresses(): void {
	bySlug.clear();
	byId.clear();
}

/*
 * Resolves the bucket a request is addressed to.
 *
 * `undefined` for the slug means the bare address — the default bucket, whose issuer is the server's
 * own and whose endpoints are the paths every client integrated before tenancy already uses.
 *
 * `null` means the address names no bucket. The caller answers that as "not found" rather than
 * falling back to the default bucket: falling back would serve one population's endpoints at another
 * population's address, and would make a typo in a URL look like it worked.
 */
export async function bucketAtAddress(
	slug: string | undefined
): Promise<UserBucket | null> {
	if (slug === undefined) {
		return getBucketStore().find(DEFAULT_BUCKET_ID);
	}

	const cached = bySlug.get(slug);
	if (cached) return cached;

	const bucket = await getBucketStore().findBySlug(slug);
	if (!bucket) return null;

	if (!isAddressable(bucket)) return null;

	bySlug.set(slug, bucket);
	return bucket;
}

/*
 * The bucket a route is serving, for a route mounted twice — once bare, once beneath `/:bucket`.
 *
 * The bare mount passes nothing and gets the default bucket, which is the honest answer: its address
 * is the root and its issuer is the server's own. The prefixed mount passes the segment the router
 * captured, and an address naming no bucket is refused rather than falling back — falling back would
 * serve one population's endpoints at another population's address, and would make a mistyped URL
 * look like it worked.
 *
 * Every prefixed route calls this, which is what keeps a handler from being able to forget: the
 * alternative is a default that silently mints tokens whose `iss` disagrees with the metadata that
 * advertised the endpoint they came from.
 */
export async function requestBucketFor(
	slug: string | undefined
): Promise<RequestBucket> {
	if (slug === undefined) return DEFAULT_REQUEST_BUCKET;

	const bucket = await bucketAtAddress(slug);
	if (!bucket) throw new UnknownBucket();
	return { _id: bucket._id, slug: bucket.slug };
}

/*
 * The address of the bucket that issued something, from the record id that something stored.
 *
 * A token records the bucket's **id** rather than its slug, because the id is the durable key and a
 * slug is a name — even fixed at creation, storing the name would mean a token's issuer was derived
 * from a copy rather than from the record. So the slug is looked up here, and `issuerFor` builds the
 * identifier from it.
 *
 * The default bucket short-circuits with no lookup at all: its issuer is the server's own, which is
 * also the right answer for anything minted before buckets became tenants and recording nothing.
 */
export async function issuingBucket(
	bucketId: string | undefined
): Promise<RequestBucket> {
	if (!bucketId || bucketId === DEFAULT_BUCKET_ID) {
		return DEFAULT_REQUEST_BUCKET;
	}

	const cached = byId.get(bucketId);
	if (cached) return cached;

	const bucket = await getBucketStore().find(bucketId);
	/*
	 * A bucket that no longer exists still has tokens in circulation. Their issuer is not the default
	 * bucket's — answering that would let a deleted tenant's tokens validate against the surviving
	 * server — so the identifier keeps the id it was minted under, which matches nothing and is exactly
	 * the outcome wanted.
	 */
	const resolved: RequestBucket = bucket
		? { _id: bucket._id, slug: bucket.slug }
		: { _id: bucketId, slug: undefined };

	byId.set(bucketId, resolved);
	return resolved;
}
