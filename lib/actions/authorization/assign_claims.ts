import { merge } from 'lib/helpers/_/object.js';
import instance from '../../helpers/weak_cache.ts';

/*
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 */
export default function assignClaims(oidc) {
	const { params } = oidc;

	if (
		params.claims !== undefined &&
		instance(oidc.provider).features.claimsParameter.enabled
	) {
		oidc.claims = params.claims;
	}

	if (
		params.max_age !== undefined ||
		oidc.client.requireAuthTime ||
		oidc.prompts.has('login')
	) {
		merge(oidc.claims, { id_token: { auth_time: { essential: true } } });
	}

	const acrValues = params.acr_values;

	if (acrValues) {
		merge(oidc.claims, {
			id_token: { acr: { values: acrValues.split(' ') } }
		});
	}
}
