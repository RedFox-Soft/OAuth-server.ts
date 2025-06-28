import { ISSUER } from 'lib/configs/env.js';
import { routeNames } from 'lib/consts/param_list.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { ApplicationConfig } from './application.js';
import { dPoPSigningAlgValues } from './jwaAlgorithms.js';

const discovery = {
	issuer: ISSUER,
	response_modes_supported: ['form_post', 'query'],
	response_types_supported: ['none', 'code'],
	code_challenge_methods_supported: ['S256'],

	// par.enabled is used to determine if the pushed_authorization_request_endpoint is available
	pushed_authorization_request_endpoint: `${ISSUER}${routeNames.pushed_authorization_request}`,
	request_uri_parameter_supported: false,
	require_pushed_authorization_requests: false,

	introspection_endpoint: `${ISSUER}${routeNames.introspect}`,

	dpop_signing_alg_values_supported: dPoPSigningAlgValues
};

export function calculateDiscovery() {
	const copy = { ...discovery };
	copy.require_pushed_authorization_requests =
		ClientDefaults['authorization.requirePushedAuthorizationRequests'];
	copy.request_uri_parameter_supported = ApplicationConfig['par.enabled'];

	if (ApplicationConfig['responseMode.jwt.enabled']) {
		copy.response_modes_supported.push('jwt', 'query.jwt', 'form_post.jwt');
	}

	return copy;
}
