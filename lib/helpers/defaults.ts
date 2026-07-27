import { base as defaultPolicy } from './interaction_policy/index.ts';

function makeDefaults() {
	const defaults = {
		/*
		 * clientDefaults
		 *
		 * description: Default client metadata to be assigned when unspecified by the client metadata,
		 * e.g. during Dynamic Client Registration or for statically configured clients.
		 */
		clientDefaults: {
			id_token_signed_response_alg: 'RS256',
			token_endpoint_auth_method: 'client_secret_basic'
		},

		/*
		 * conformIdTokenClaims
		 *
		 * title: ID Token only contains End-User claims when the requested `response_type` is `id_token`
		 */
		conformIdTokenClaims: true,

		/*
		 * discovery
		 *
		 * description: Pass additional properties to this object to extend the discovery document
		 */
		discovery: {
			claim_types_supported: ['normal'],
			claims_locales_supported: undefined,
			display_values_supported: undefined,
			op_policy_uri: undefined,
			op_tos_uri: undefined,
			service_documentation: undefined,
			ui_locales_supported: undefined
		},

		/*
		 * interactions
		 *
		 * description: Holds the configuration for interaction policy and a URL to send end-users to
		 *   when the policy decides to require interaction.
		 *
		 * @nodefault
		 */
		interactions: {
			policy: defaultPolicy()
		}
	};

	return defaults;
}

export default makeDefaults;
export const defaults = makeDefaults();
