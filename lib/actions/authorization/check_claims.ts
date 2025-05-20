import { InvalidRequest } from '../../helpers/errors.ts';
import instance from '../../helpers/weak_cache.ts';
import isPlainObject from '../../helpers/_/is_plain_object.ts';

/*
 * If claims parameter is provided and supported handles its validation
 * - should not be combined with rt none
 * - should be JSON serialized object with id_token or userinfo properties as objects
 * - claims.userinfo should not be used if authorization result is not access_token
 *
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 */
export default async function checkClaims(ctx) {
	const { params } = ctx.oidc;

	if (params.claims !== undefined) {
		const { claimsParameter, userinfo } = instance(ctx.oidc.provider).features;

		if (claimsParameter.enabled) {
			if (params.response_type === 'none') {
				throw new InvalidRequest(
					'claims parameter should not be combined with response_type none'
				);
			}
			if (params.claims.userinfo && !userinfo.enabled) {
				throw new InvalidRequest(
					'claims.userinfo should not be used since userinfo endpoint is not supported'
				);
			}

			await claimsParameter.assertClaimsParameter?.(
				ctx,
				params.claims,
				ctx.oidc.client
			);
		}
	}
}
