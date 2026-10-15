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
	| { kind: 'subdomain'; host: string }
	| { kind: 'host'; host: string }
	| { kind: 'none' };

/*
 * `instanceHost` is ISSUER's host as the server rendered it (`window.PROPS.instanceHost`), passed in
 * because this module is in the browser bundle and must not read the environment itself.
 */
export function bucketAddressFor(
	bucket: {
		_id: string;
		slug?: string;
		host?: string;
		subdomain?: true;
	},
	instanceHost: string
): BucketAddress {
	if (isServedAtTheRoot(bucket._id)) return { kind: 'root' };
	/*
	 * Before the slug, because the two are alternatives and a host-addressed bucket carries no slug at
	 * all. Testing the slug first would report every one of them as `none` — "reachable nowhere" for a
	 * bucket that is in fact reachable at an origin of its own, in the one column an operator copies.
	 */
	if (bucket.host) return { kind: 'host', host: bucket.host };
	if (!bucket.slug) return { kind: 'none' };
	/*
	 * A subdomain bucket carries a slug as a path bucket does; only the marker tells them apart, so it is
	 * read before the path is assumed — the server's `addressOf` asks in the same order.
	 */
	if (bucket.subdomain) {
		return { kind: 'subdomain', host: `${bucket.slug}.${instanceHost}` };
	}
	return { kind: 'prefix', path: `/${bucket.slug}` };
}

/*
 * The origin an own-origin bucket answers at. The scheme is the console page's own, which is ISSUER's
 * wherever the console is served, so a development instance on plain HTTP is not shown an `https://`
 * address it does not answer. Read lazily: every caller renders after the browser fetched the rows.
 */
export function originOf(host: string): string {
	const protocol =
		typeof window === 'undefined' ? 'https:' : window.location.protocol;
	return `${protocol}//${host}`;
}
