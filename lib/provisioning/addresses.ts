import { addressOf, issuerFor, type RequestBucket } from '../configs/issuer.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { SCIM_BASE_PATH } from '../consts/scim.js';
import { routeNames } from '../consts/param_list.js';

/*
 * A bucket's SCIM base URL: beneath its issuer, so it follows every addressing form (root, path, host)
 * without a SCIM-specific rule. `null` where the bucket has no SCIM at all:
 *
 *   - the administrators' bucket, which is served at the root and so would otherwise claim the default
 *     bucket's URL — and whose people a directory must never provision;
 *   - a bucket with no address yet, whose issuer is a placeholder built from its record id. Handing that
 *     out would give a customer a URL that silently stops working when the bucket is given a slug.
 */
export function scimBaseUrl(bucket: RequestBucket): string | null {
	if (bucket._id === ADMIN_BUCKET_ID) return null;
	if (addressOf(bucket).kind === 'unaddressed') return null;
	return `${issuerFor(bucket)}${SCIM_BASE_PATH}`;
}

/*
 * RFC 9728 §3.1: the well-known segment is inserted between the host and the resource's path, so a
 * resource at `/acme/scim/v2` publishes at `/.well-known/oauth-protected-resource/acme/scim/v2`.
 */
export function scimMetadataUrl(bucket: RequestBucket): string | null {
	const base = scimBaseUrl(bucket);
	if (!base) return null;
	const url = new URL(base);
	return `${url.origin}/.well-known/oauth-protected-resource${url.pathname}`;
}

export function tokenEndpointFor(bucket: RequestBucket): string {
	return `${issuerFor(bucket)}${routeNames.token}`;
}
