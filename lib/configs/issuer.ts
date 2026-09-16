import { ISSUER } from './env.js';
import { DEFAULT_BUCKET_ID } from '../admin/consts.js';

/*
 * Just enough of a bucket to derive an address from, and it lives here rather than beside the request
 * context for a reason that cost a debugging session: the models mint tokens and therefore need to
 * resolve an issuer, so anything they reach must not reach back into the request pipeline. This module
 * imports the environment and two constants and nothing else.
 */
export type RequestBucket = { _id: string; slug?: string };

/*
 * The bucket a request belongs to when its address names none — every request to a bare path, and
 * therefore every request this server answered before buckets became tenants.
 */
export const DEFAULT_REQUEST_BUCKET: RequestBucket = {
	_id: DEFAULT_BUCKET_ID,
	slug: 'default'
};

/*
 * The one place that knows the default bucket is addressed at the root.
 *
 * Every other bucket is a tenant with its own issuer identifier — `<ISSUER>/<name>` — and serves its
 * endpoints beneath it. The default bucket keeps the bare issuer it already has, because an issuer
 * identifier is a promise already made: clients are configured against it and tokens carrying it are
 * in circulation. That asymmetry is the whole compatibility story of this feature, and it costs
 * exactly one branch, here.
 *
 * The parameter is required, deliberately. A caller that cannot say which bucket it is serving has
 * not decided, and a default argument would turn that undecided case into a silently wrong issuer —
 * a token whose `iss` does not match the metadata that advertised its endpoints, which clients reject
 * with an error naming neither cause. Better to fail to compile.
 *
 * Never inline this branch. Across the thirty call sites that read the issuer it would become thirty
 * chances to forget the default case.
 */
export function issuerFor(bucket: RequestBucket): string {
	if (bucket._id === DEFAULT_BUCKET_ID) {
		return ISSUER;
	}
	/*
	 * The slug, not the record id: the id is internal and may be a 43-character nanoid, while the slug
	 * is what an operator chose and what a client sees. A bucket that has no slug yet cannot be
	 * addressed, so its id is the only thing left to build an identifier from — that case disappears
	 * once slugs are assigned, and until then it keeps the derivation total rather than throwing.
	 */
	return `${ISSUER}/${bucket.slug ?? bucket._id}`;
}

/*
 * The path segment a bucket's endpoints live beneath, empty for the default bucket. Separate from
 * `issuerFor` because routing needs the segment without the origin, and deriving one by string
 * surgery on the other is how the two drift apart.
 */
export function pathPrefixFor(bucket: RequestBucket): string {
	if (bucket._id === DEFAULT_BUCKET_ID) {
		return '';
	}
	return `/${bucket.slug ?? bucket._id}`;
}
