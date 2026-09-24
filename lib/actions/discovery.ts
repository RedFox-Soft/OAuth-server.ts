import { Elysia } from 'elysia';
import defaults from '../helpers/_/defaults.ts';
import {
	calculateDiscovery,
	featuresKeyMap,
	metadataClassification,
	type FeatureFlagKey
} from 'lib/configs/discoverySupport.js';
import { ApplicationConfig } from '../configs/application.js';
import {
	DiscoveryResponse,
	OAuthError,
	type DiscoveryDocument
} from 'lib/shared/response_schemas.js';
import { corsOpen } from 'lib/plugins/cors.js';
import {
	bucketAtAddress,
	bucketAtHost,
	isCanonicalHost,
	isWithinDeploymentDomain
} from 'lib/admin/auth/bucketAddress.js';
import { hostOfRequest, normaliseHost } from 'lib/consts/request_host.js';

type BucketAddress = { _id: string; slug?: string; host?: string };

// Booleans whose `false` value is meaningful and must survive the falsy-value sweep.
const MEANINGFUL_FALSE = new Set<string>(['request_uri_parameter_supported']);

/*
 * The stages both metadata documents share, in the order they must run.
 *
 * Callers hand in a body that has already been narrowed to the members belonging to their document;
 * everything after that point is identical, which is what keeps the two documents agreeing on every
 * member they have in common.
 */
function gateAndExtend(body: DiscoveryDocument): DiscoveryDocument {
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
	const body: DiscoveryDocument = calculateDiscovery(bucket);

	/*
	 * Narrow to the OAuth surface BEFORE gating. Order is load-bearing: the override stage
	 * inside gateAndExtend fills only absent members, so filtering after it would silently
	 * delete a value an operator had explicitly set — and only for the members they cared
	 * enough to configure.
	 */
	for (const [key, { audience }] of Object.entries(metadataClassification)) {
		if (audience === 'oidc') {
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
	build: (bucket?: BucketAddress) => DiscoveryDocument,
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

/*
 * The same answer for the other address form, at the one conventional location.
 *
 * A host-addressed bucket's issuer is an origin with no path, so OIDC Discovery and RFC 8414 agree on
 * where its document lives and the two-location problem above simply does not arise — which is why
 * this serves the bare routes rather than adding a third and fourth.
 *
 * A request to the deployment's own host is the default bucket's, exactly as before hostnames existed.
 * Anything else must name a bucket or be refused: serving the default population's metadata at an
 * address it does not answer at is the same defect `forSlug` refuses one line up.
 */
async function forHost(
	host: string | null,
	build: (bucket?: BucketAddress) => DiscoveryDocument,
	set: { status?: number | string }
) {
	const normalised = normaliseHost(host ?? undefined);
	if (normalised === null || isCanonicalHost(normalised)) return build();

	const bucket = await bucketAtHost(normalised);
	if (bucket) return build(bucket);

	/*
	 * Not found only inside the deployment's own domain, where a name can only be a tenant's. A name
	 * outside it — `localhost`, the platform's own, whatever a health check uses — is another way of
	 * reaching this deployment, and answering it with the instance's own metadata is what every request
	 * got before hostnames existed.
	 */
	if (isWithinDeploymentDomain(normalised)) {
		set.status = 404;
		return { error: 'not_found' };
	}
	return build();
}

// corsOpen must precede the routes: an Elysia hook only affects routes declared after it. A JavaScript
// client cannot discover a deployment it is not allowed to read (OIDC Discovery 1.0 §4, RFC 8414 §3).
export const discovery = new Elysia()
	.use(corsOpen)
	// The metadata, an address naming no bucket (404, `not_found`), or the shared server_error body.
	.guard({
		response: { 200: DiscoveryResponse, 404: OAuthError, 500: OAuthError }
	})
	.get('/.well-known/openid-configuration', ({ request, set }) =>
		forHost(hostOfRequest(request), openidConfiguration, set)
	)
	.get('/.well-known/oauth-authorization-server', ({ request, set }) =>
		forHost(hostOfRequest(request), oauthAuthorizationServer, set)
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
