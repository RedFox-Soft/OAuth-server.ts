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

// corsOpen must precede the routes: an Elysia hook only affects routes declared after it. A JavaScript
// client cannot discover a deployment it is not allowed to read (OIDC Discovery 1.0 §4, RFC 8414 §3).
export const discovery = new Elysia()
	.use(corsOpen)
	.get(
		'/.well-known/openid-configuration',
		function () {
			// Compute the full candidate document from the live ApplicationConfig, then gate it.
			return gateAndExtend(calculateDiscovery());
		},
		{
			response: { 200: DiscoveryResponse, 500: OAuthError }
		}
	)
	.get(
		'/.well-known/oauth-authorization-server',
		function () {
			const body: Record<string, unknown> = calculateDiscovery();

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
		},
		{
			response: { 200: DiscoveryResponse, 500: OAuthError }
		}
	);
