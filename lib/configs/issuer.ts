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
	if (isServedAtTheRoot(bucket._id)) {
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
 * The path segment a bucket's endpoints live beneath, empty for a bucket served at the root. Separate
 * from `issuerFor` because routing needs the segment without the origin, and deriving one by string
 * surgery on the other is how the two drift apart.
 */
export function pathPrefixFor(bucket: RequestBucket): string {
	if (isServedAtTheRoot(bucket._id)) {
		return '';
	}
	return `/${bucket.slug ?? bucket._id}`;
}
