import { Elysia } from 'elysia';
import defaults from '../helpers/_/defaults.ts';
import {
	calculateDiscovery,
	featuresKeyMap,
	metadataClassification,
	type FeatureFlagKey
} from 'lib/configs/discoverySupport.js';
import { ApplicationConfig } from '../configs/application.js';
import { DiscoveryResponse, OAuthError } from 'lib/shared/response_schemas.js';
import { corsOpen } from 'lib/plugins/cors.js';
import { bucketAtAddress } from 'lib/admin/auth/bucketAddress.js';

type BucketAddress = { _id: string; slug?: string };

// Booleans whose `false` value is meaningful and must survive the falsy-value sweep.
const MEANINGFUL_FALSE = new Set<string>(['request_uri_parameter_supported']);

/*
 * The stages both metadata documents share, in the order they must run.
 *
 * Callers hand in a body that has already been narrowed to the members belonging to their document;
 * everything after that point is identical, which is what keeps the two documents agreeing on every
 * member they have in common.
 */
function gateAndExtend(body: Record<string, unknown>): Record<string, unknown> {
	const keysToDelete = new Set<string>();

	// Prune keys whose governing feature flag is disabled (multi-feature keys are listed
	// under each flag, so any disabled flag removes them).
	for (const flag of Object.keys(featuresKeyMap) as FeatureFlagKey[]) {
		if (!ApplicationConfig[flag]) {
			featuresKeyMap[flag]?.forEach((key) => keysToDelete.add(key));
		}
	}

	// Drop keys left with a non-meaningful `false` value.
	for (const key of Object.keys(body)) {
		if (body[key] === false && !MEANINGFUL_FALSE.has(key)) {
			keysToDelete.add(key);
		}
	}

	// Delete collected keys in a separate pass
	keysToDelete.forEach((key) => {
		// eslint-disable-next-line @typescript-eslint/no-dynamic-delete
		delete body[key];
	});

	// Operator-supplied discovery overrides are applied last and only fill missing keys.
	defaults(body, ApplicationConfig.discovery);
	return body;
}

/* Compute the full candidate document from the live ApplicationConfig, then gate it. */
function openidConfiguration(bucket?: BucketAddress) {
	return gateAndExtend(calculateDiscovery(bucket));
}

function oauthAuthorizationServer(bucket?: BucketAddress) {
	const body: Record<string, unknown> = calculateDiscovery(bucket);

	/*
	 * Narrow to the OAuth surface BEFORE gating. Order is load-bearing: the override stage
	 * inside gateAndExtend fills only absent members, so filtering after it would silently
	 * delete a value an operator had explicitly set — and only for the members they cared
	 * enough to configure.
	 */
	for (const key of Object.keys(body)) {
		if (metadataClassification[key as never]?.audience === 'oidc') {
			// eslint-disable-next-line @typescript-eslint/no-dynamic-delete
			delete body[key];
		}
	}

	return gateAndExtend(body);
}

/*
 * A path-bearing issuer has two well-known locations, and the two specifications build them
 * differently: OIDC Discovery appends the segment to the issuer, RFC 8414 inserts it between the host
 * and the issuer's path. For a bucket named `acme` that is `/acme/.well-known/openid-configuration`
 * and `/.well-known/oauth-authorization-server/acme` — structurally different URLs for one issuer.
 *
 * Both are served, and both return the document the other would. Serving only the appended form is
 * the failure that passes every local test and fails a conformance run, because nothing in a local
 * suite asks for a URL nobody wrote down.
 *
 * The bare routes below are the default bucket's, unchanged: its issuer has no path, so the two
 * conventions collapse onto the paths this server already published.
 */
async function forSlug(
	slug: string,
	build: (bucket?: BucketAddress) => Record<string, unknown>,
	set: { status?: number | string }
) {
	const bucket = await bucketAtAddress(slug);
	if (!bucket) {
		/*
		 * An address naming no bucket is not found, rather than quietly served as the default bucket's:
		 * falling back would answer one population's metadata at another's address and make a typo in a
		 * URL look like it worked.
		 */
		set.status = 404;
		return { error: 'not_found' };
	}
	return build(bucket);
}

// corsOpen must precede the routes: an Elysia hook only affects routes declared after it. A JavaScript
// client cannot discover a deployment it is not allowed to read (OIDC Discovery 1.0 §4, RFC 8414 §3).
export const discovery = new Elysia()
	.use(corsOpen)
	.get('/.well-known/openid-configuration', () => openidConfiguration(), {
		response: { 200: DiscoveryResponse, 500: OAuthError }
	})
	.get(
		'/.well-known/oauth-authorization-server',
		() => oauthAuthorizationServer(),
		{
			response: { 200: DiscoveryResponse, 500: OAuthError }
		}
	)
	/* OIDC Discovery 1.0 §4: the well-known segment is appended to the issuer. */
	.get('/:bucket/.well-known/openid-configuration', ({ params, set }) =>
		forSlug(params.bucket, openidConfiguration, set)
	)
	.get('/:bucket/.well-known/oauth-authorization-server', ({ params, set }) =>
		forSlug(params.bucket, oauthAuthorizationServer, set)
	)
	/* RFC 8414 §3: for an issuer with a path, the well-known segment is inserted before it. */
	.get('/.well-known/openid-configuration/:bucket', ({ params, set }) =>
		forSlug(params.bucket, openidConfiguration, set)
	)
	.get('/.well-known/oauth-authorization-server/:bucket', ({ params, set }) =>
		forSlug(params.bucket, oauthAuthorizationServer, set)
	);
