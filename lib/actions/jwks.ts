import { Elysia } from 'elysia';
import { routeNames } from 'lib/consts/param_list.js';
import { corsOpen } from 'lib/plugins/cors.js';
import { JwksResponse, OAuthError } from 'lib/shared/response_schemas.js';
import { requestBucketFor } from 'lib/admin/auth/bucketAddress.js';
import { hostOfRequest } from 'lib/consts/request_host.js';
import { keysFor } from 'lib/keys/issuer_keys.js';

/*
 * The key set of the issuer this address belongs to: the root's at the bare path and the deployment's
 * own host, a bucket's own beneath its path or at its hostname.
 *
 * Mounted at both the bare path and beneath `/:bucket`, and resolved the way every other endpoint
 * resolves its bucket — host first, then path — so a tenant hostname serves that tenant's keys. An
 * address naming no bucket is refused as not found by `requestBucketFor`, and never answered with the
 * root's keys: a resource server that followed a mistyped `jwks_uri` would otherwise trust a set no
 * token it receives was signed with, and nothing would say why.
 */
// corsOpen must precede the route: an Elysia hook only affects routes declared after it, so moving
// this below the .get() silently stops emitting the header a browser needs to read the key set.
export const jwks = new Elysia().use(corsOpen).get(
	routeNames.jwks,
	async ({ set, params, request }) => {
		const bucket = await requestBucketFor(
			(params as { bucket?: string } | undefined)?.bucket,
			hostOfRequest(request)
		);
		// Read per request, not captured: the root set is mutated in place when a key is hot-applied,
		// and a bucket's is replaced when its cache entry expires.
		const { keys } = (await keysFor(bucket)).publicJWKS;
		set.headers['content-type'] = 'application/jwk-set+json; charset=utf-8';
		return { keys };
	},
	{ response: { 200: JwksResponse, 404: OAuthError } }
);
