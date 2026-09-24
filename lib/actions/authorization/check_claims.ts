import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { InvalidRequest } from '../../helpers/errors.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { assertClaimsParameter } from '../../addon/index.js';
import { CLAIMS_MEMBERS } from 'lib/consts/param_list.js';
import { ignoreUnknownIn } from 'lib/plugins/ignore_unknown_params.js';

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
export default async function checkClaims(oidc: OIDCContext<PipelineParams>) {
	const { params } = oidc;

	if (params.claims !== undefined) {
		if (ApplicationConfig['claimsParameter.enabled']) {
			/*
			 * Deleted rather than merely tolerated, and deleted here rather than at the schema, because
			 * every pipeline reaches this function before anything persists its parameters: PAR
			 * serialises `oidc.params` into the request object it stores, and the interaction record
			 * copies them again. A member carried instead of dropped is a member a client can make this
			 * server keep. Same rule as the one the endpoints live under for unrecognized *parameters*
			 * (lib/plugins/ignore_unknown_params.ts), one level in.
			 */
			ignoreUnknownIn(CLAIMS_MEMBERS, params.claims);

			if (params.response_type === 'none') {
				throw new InvalidRequest(
					'claims parameter should not be combined with response_type none'
				);
			}
			if (params.claims.userinfo && !ApplicationConfig['userinfo.enabled']) {
				throw new InvalidRequest(
					'claims.userinfo should not be used since userinfo endpoint is not supported'
				);
			}

			await assertClaimsParameter(oidc, params.claims, oidc.client);
		}
	}
}
