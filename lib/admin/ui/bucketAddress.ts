import { isServedAtTheRoot } from '../consts.js';

/*
 * Where a bucket's endpoints actually are, as the console reports it.
 *
 * Three outcomes, not two, and conflating the first with the second is what this exists to stop. The
 * console rendered the slug whenever there was one, so the default bucket — which holds the slug
 * `default` and is served at the root — was listed at `/default`, an address that answers 404. The
 * Address column is precisely what an operator copies when pointing a client at a bucket, so the one
 * column that must not be approximately right was.
 *
 * `root` and `none` are different states rather than two words for unaddressable. A bucket served at
 * the root is reachable at every bare endpoint this server has always published; a bucket with no slug
 * is reachable nowhere until an operator gives it one.
 *
 * Extracted from the table because a decision embedded in a JSX render function cannot be checked
 * against the router that has to agree with it — which is the whole of `bucket_address.spec.ts`.
 */
export type BucketAddress =
	| { kind: 'root' }
	| { kind: 'prefix'; path: string }
	| { kind: 'host'; host: string }
	| { kind: 'none' };

export function bucketAddressFor(bucket: {
	_id: string;
	slug?: string;
	host?: string;
}): BucketAddress {
	if (isServedAtTheRoot(bucket._id)) return { kind: 'root' };
	/*
	 * Before the slug, because the two are alternatives and a host-addressed bucket carries no slug at
	 * all. Testing the slug first would report every one of them as `none` — "reachable nowhere" for a
	 * bucket that is in fact reachable at an origin of its own, in the one column an operator copies.
	 */
	if (bucket.host) return { kind: 'host', host: bucket.host };
	if (!bucket.slug) return { kind: 'none' };
	return { kind: 'prefix', path: `/${bucket.slug}` };
}
