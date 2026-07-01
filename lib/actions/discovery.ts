import { Elysia } from 'elysia';
import defaults from '../helpers/_/defaults.ts';
import instance from '../helpers/weak_cache.ts';
import { provider } from 'lib/index.js';
import {
	calculateDiscovery,
	featuresKeyMap,
	type FeatureFlagKey
} from 'lib/configs/discoverySupport.js';
import { ApplicationConfig } from '../configs/application.js';
import { DiscoveryResponse, OAuthError } from 'lib/shared/response_schemas.js';

// Booleans whose `false` value is meaningful and must survive the falsy-value sweep.
const MEANINGFUL_FALSE = new Set<string>(['request_uri_parameter_supported']);

export const discovery = new Elysia().get(
	'/.well-known/openid-configuration',
	function () {
		const { configuration } = instance(provider);

		// Compute the full candidate document from the live ApplicationConfig, then gate it.
		const body: Record<string, unknown> = calculateDiscovery();

		// Prune keys whose governing feature flag is disabled (multi-feature keys are listed
		// under each flag, so any disabled flag removes them).
		for (const flag of Object.keys(featuresKeyMap) as FeatureFlagKey[]) {
			if (!ApplicationConfig[flag]) {
				featuresKeyMap[flag]?.forEach((key) => {
					delete body[key];
				});
			}
		}

		// Drop keys left with a non-meaningful `false` value.
		for (const key of Object.keys(body)) {
			if (body[key] === false && !MEANINGFUL_FALSE.has(key)) {
				delete body[key];
			}
		}

		// Operator-supplied discovery overrides are applied last and only fill missing keys.
		defaults(body, configuration.discovery);
		return body;
	},
	{
		response: { 200: DiscoveryResponse, 500: OAuthError }
	}
);
