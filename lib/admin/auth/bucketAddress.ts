import { getBucketStore } from '../../adapters/index.js';
import { recordHostArrival } from './hostArrivals.js';
import { DEFAULT_BUCKET_ID, isServedAtTheRoot } from '../consts.js';
import type { UserBucket } from '../../adapters/types.js';
import { UnknownBucket } from '../../helpers/errors.js';
import {
	DEFAULT_REQUEST_BUCKET,
	type RequestBucket
} from '../../configs/issuer.js';
import { ISSUER } from '../../configs/env.js';
import { canonicalHostOf, normaliseHost } from '../../consts/request_host.js';

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
 * The same cache for the other address form, with one difference worth stating: a hostname is NOT
 * immutable the way a slug is. The address-change operation writes it, so this map must be cleared
 * when it does — `forgetBucketAddresses` is that call, and forgetting it leaves a bucket answering at
 * its old address out of cache after a move, which is precisely the second issuer identifier the move
 * exists to avoid.
 */
const byHost = new Map<string, UserBucket>();

/*
 * The host this deployment itself answers at, derived once from the canonical URL.
 *
 * A request arriving here is addressed by *path*, exactly as every request was before hostnames
 * existed. Anything else is a tenant's own address, or nothing.
 */
const CANONICAL_HOST = canonicalHostOf(ISSUER);

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
export function isAddressable(bucket: {
	_id: string;
	slug?: string;
	host?: string;
}): boolean {
	/*
	 * Which buckets are served at the root is one predicate in `admin/consts.ts` rather than a second
	 * opinion held here. A bucket reachable at a prefixed address but issuing the instance's identifier — or the
	 * reverse — is exactly the mismatch that made a genuine sign-in produce a token no client would
	 * accept, and two lists of reserved ids is how that comes back.
	 *
	 * Either address form counts. A host-addressed bucket carries no slug — the two are alternatives, not
	 * layers — so testing the slug alone would declare every such bucket unaddressable and refuse every
	 * request to it.
	 */
	return Boolean(bucket.slug || bucket.host) && !isServedAtTheRoot(bucket._id);
}

export function forgetBucketAddresses(): void {
	bySlug.clear();
	byId.clear();
	byHost.clear();
}

/*
 * Whether a request's host is the deployment's own rather than a tenant's.
 *
 * A deployment whose canonical URL cannot be parsed resolves no tenant at all: every host reads as
 * unknown, which refuses requests rather than serving one population at another's address. That is the
 * right way round for a misconfiguration nobody can act on from inside a request.
 */
export function isCanonicalHost(host: string | null): boolean {
	return CANONICAL_HOST !== null && host === CANONICAL_HOST;
}

/*
 * Whether a host that named no bucket should be refused, or served as the deployment's own.
 *
 * The distinction is not pedantry; without it this feature breaks every deployment. A server is
 * reachable at more names than its canonical one — `localhost` in development, the platform's own
 * `*.fly.dev` name, the internal address a health check uses — and refusing all of them because they
 * are not the canonical host would take the deployment off the air for everything except the exact
 * URL an operator typed into `ISSUER`.
 *
 * So the rule keys on the deployment's **own domain**, which is the only place a tenant can live:
 *
 *   - a name beneath the canonical host that no bucket holds is a *typo of a tenant address*, and is
 *     refused, because serving the default population there would make the mistake look like it worked;
 *   - a name outside it is another way of reaching this deployment, and resolves by path exactly as
 *     every request did before hostnames existed.
 */
export function isWithinDeploymentDomain(host: string): boolean {
	return (
		CANONICAL_HOST !== null &&
		(host === CANONICAL_HOST || host.endsWith(`.${CANONICAL_HOST}`))
	);
}

/*
 * The bucket a hostname addresses, or null when it names none.
 *
 * Null is refused by the caller rather than falling back to the default bucket, for the same reason
 * `bucketAtAddress` records about an unknown slug: falling back would serve one population's endpoints
 * at another population's address, and would make a typo in a hostname look like it worked.
 */
export async function bucketAtHost(host: string): Promise<UserBucket | null> {
	const cached = byHost.get(host);
	if (cached) {
		recordHostArrival(cached._id, host);
		return cached;
	}

	const bucket = await getBucketStore().findByHost(host);
	if (!bucket) return null;
	if (!isAddressable(bucket)) return null;

	byHost.set(host, bucket);
	/*
	 * Recorded on the cached path too, not only on a miss. The cache is what makes resolution cheap, so
	 * recording only on a miss would report the first request after a restart and nothing else — an
	 * "address last reached" that mostly measures uptime.
	 */
	recordHostArrival(bucket._id, host);
	return bucket;
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
	slug: string | undefined,
	requestHost: string | null | undefined
): Promise<RequestBucket> {
	const host = normaliseHost(requestHost ?? undefined);

	/*
	 * The host is asked first, and only a request arriving at the deployment's own host falls through to
	 * the path. A tenant's host is an address in its own right, so a path segment beneath it is an
	 * ordinary path — honouring it as well would give that bucket a second address and therefore a
	 * second issuer identifier, which is the one thing an issuer identifier may not have.
	 */
	if (host !== null && !isCanonicalHost(host)) {
		const addressed = await bucketAtHost(host);
		if (addressed) {
			/* One bucket, one address: a leading segment here names no bucket, and honouring it would
			 * give that bucket a second address and therefore a second issuer identifier. */
			if (slug !== undefined) throw new UnknownBucket();
			return { _id: addressed._id, host: addressed.host };
		}

		/*
		 * Refused only inside the deployment's own domain, where the only thing a name can be is a
		 * tenant's — so one that holds no bucket is a typo, and serving the default population there
		 * would make the mistake look like it worked. Anything else is another way of reaching this
		 * deployment and falls through to the path, unchanged.
		 */
		if (isWithinDeploymentDomain(host)) throw new UnknownBucket();
	}

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
