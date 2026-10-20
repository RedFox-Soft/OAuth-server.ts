import { ISSUER } from './env.js';
import {
	ADMIN_BUCKET_ID,
	DEFAULT_BUCKET_ID,
	isServedAtTheRoot
} from '../admin/consts.js';

/*
 * Just enough of a bucket to derive an address from, and it lives here rather than beside the request
 * context for a reason that cost a debugging session: the models mint tokens and therefore need to
 * resolve an issuer, so anything they reach must not reach back into the request pipeline. This module
 * imports the environment and one import-free constants module, and nothing else.
 */
export type RequestBucket = {
	_id: string;
	slug?: string;
	host?: string;
	subdomain?: true;
};

/*
 * How a bucket is addressed — the one place the question is answered.
 *
 * There are three states and two fields, so no single stored value says which one a bucket is in:
 * `slug` is an address for a named bucket and merely a name for the two served at the root, and a
 * host-addressed bucket carries a hostname instead of a slug. Every consumer therefore reads this
 * rather than asking its own two questions — `issuerFor` and `pathPrefixFor` below, the request
 * resolver, the session cookie's name, and the console.
 *
 * It exists for the reason `isAddressable` exists one module over, which its own comment records: a
 * bucket reachable at one address but issuing another's identifier is the mismatch that made a genuine
 * sign-in produce a token no client would accept, and two opinions about a bucket's address is how that
 * comes back. Adding a third state to two opinions would be worse than adding it to one.
 */
export type BucketAddress =
	| { kind: 'root' }
	| { kind: 'path'; segment: string }
	| { kind: 'host'; host: string }
	| { kind: 'subdomain'; label: string }
	| { kind: 'unaddressed' };

export function addressOf(bucket: RequestBucket): BucketAddress {
	if (isServedAtTheRoot(bucket._id)) return { kind: 'root' };
	if (bucket.host) return { kind: 'host', host: bucket.host };
	/*
	 * Before `path`, because a subdomain bucket carries a slug too: tested the other way round, every
	 * subdomain bucket would read as path-addressed and mint `<ISSUER>/<slug>` while its discovery
	 * document named its own origin (specs/101).
	 */
	if (bucket.slug && bucket.subdomain) {
		return { kind: 'subdomain', label: bucket.slug };
	}
	if (bucket.slug) return { kind: 'path', segment: bucket.slug };
	/*
	 * A bucket written before slugs existed, which `isAddressable` already refuses to route to. It is a
	 * state of its own rather than a path address built from the record id, because the two consumers
	 * below disagree about it **on purpose** and collapsing them breaks one of them:
	 *
	 *   - the issuer falls back to the id, which keeps the derivation total rather than throwing;
	 *   - the session cookie falls back to `default`, because such a bucket's clients use the bare
	 *     endpoints and share the default bucket's cookie. Naming it `_session_<id>` would write a cookie
	 *     the bare `/auth` and `/logout` never look for — the sign-in would complete and then not exist.
	 *
	 * Modelling this as `path(_id)` would have handed the id to both.
	 */
	return { kind: 'unaddressed' };
}

/*
 * The bucket a request belongs to when its address names none — every request to a bare path, and
 * therefore every request this server answered before buckets became tenants.
 */
export const DEFAULT_REQUEST_BUCKET: RequestBucket = {
	_id: DEFAULT_BUCKET_ID,
	slug: 'default'
};

/*
 * The administrators bucket, for the one caller that knows its bucket without an address to read it
 * from: the console's sign-out. Both slugs match what the seed writes, and the seed repairs them on an
 * existing record, so neither is a guess about stored data.
 */
export const ADMIN_REQUEST_BUCKET: RequestBucket = {
	_id: ADMIN_BUCKET_ID,
	slug: 'admin'
};

/*
 * The issuer identifier a bucket's tokens carry. Every bucket not served at the root is a tenant with
 * its own — `<ISSUER>/<name>` — and serves its endpoints beneath it.
 *
 * The parameter is required, deliberately. A caller that cannot say which bucket it is serving has
 * not decided, and a default argument would turn that undecided case into a silently wrong issuer —
 * a token whose `iss` does not match the metadata that advertised its endpoints, which clients reject
 * with an error naming neither cause. Better to fail to compile.
 *
 * Never inline this branch. Across the thirty call sites that read the issuer it would become thirty
 * chances to forget the root case.
 */
export function issuerFor(bucket: RequestBucket): string {
	const address = addressOf(bucket);
	switch (address.kind) {
		case 'root':
			return ISSUER;
		/*
		 * The bucket's own origin, with the scheme taken from ISSUER and never from the request. A scheme
		 * read from the request would make a token's issuer depend on how the request arrived, and would
		 * drag the request pipeline into the module the models import — the thing the note at the top of
		 * this file exists to prevent.
		 */
		case 'host':
			return `${new URL(ISSUER).protocol}//${address.host}`;
		/*
		 * A name beneath the instance's own host, derived rather than stored, so it follows `ISSUER` as a
		 * path issuer does. Scheme and port come from ISSUER: the subdomain is served by the same listener,
		 * so a development instance on `localhost:3000` serves `acme.localhost:3000`.
		 */
		case 'subdomain': {
			const instance = new URL(ISSUER);
			return `${instance.protocol}//${address.label}.${instance.host}`;
		}
		/*
		 * The slug, not the record id: the id is internal and may be a 43-character nanoid, while the slug
		 * is what an operator chose and what a client sees.
		 */
		case 'path':
			return `${ISSUER}/${address.segment}`;
		/*
		 * A bucket with no address yet. The id is the only thing left to build an identifier from, which
		 * keeps this total rather than throwing; the case disappears once a slug is assigned.
		 */
		case 'unaddressed':
			return `${ISSUER}/${bucket._id}`;
	}
}

/*
 * The name a person signing in to a bucket is shown: the name the bucket chose to show them, or else the
 * host they are at — the consent page's rule. Never `name`: the console promises an administrator that the
 * name is "only for this console", and the reserved administrators' bucket is called `Administrators`, which
 * is how every console sign-up received an email about verifying "for Administrators".
 */
export function shownNameOf(
	bucket: RequestBucket & { displayName?: string }
): string {
	return bucket.displayName || new URL(issuerFor(bucket)).host;
}

/*
 * Whether a bucket is served on an origin of its own — a hostname, or a subdomain of the instance.
 *
 * Asked wherever the answer changes behaviour: the session cookie's name, whether an interaction is bound to
 * the origin it began at, and where a resumed request returns. Each of those once tested `bucket.host`, which
 * meant the same thing while a hostname was the only origin a bucket could have; a subdomain bucket has a slug
 * and no host, and would have taken the path branch at every one of them (specs/101).
 */
export function hasOwnOrigin(bucket: RequestBucket): boolean {
	const kind = addressOf(bucket).kind;
	return kind === 'host' || kind === 'subdomain';
}

/*
 * There is deliberately no `pathPrefixFor` beside `issuerFor`. One existed, computing the segment a
 * bucket's endpoints live beneath, and nothing ever called it: the router does not build a prefix, it
 * mounts the same plugins under a dynamic `/:bucket` segment and resolves the bucket from the request
 * (`lib/index.ts`). The console does need the string, and derives it in `lib/admin/ui/bucketAddress.ts`
 * rather than here, because that module is in the browser bundle and this one reads the environment.
 * Restoring the function to remove that duplication would put `ISSUER` in the client build.
 */
