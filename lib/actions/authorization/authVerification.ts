import { type Static } from 'elysia';
import { AuthorizationParameters } from 'lib/consts/param_list.js';
import { globalConfiguration } from 'lib/globalConfiguration.js';
import { NotSupportedError } from 'lib/helpers/errors.js';
import { authorizationPKCE } from 'lib/helpers/pkce.js';

type auth = Omit<Static<typeof AuthorizationParameters>, 'client_id'>;

export function authVerification(params: auth) {
	const {
		features: {
			claimsParameter,
			dPoP,
			resourceIndicators,
			richAuthorizationRequests,
			webMessageResponseMode,
			requestObjects,
			pushedAuthorizationRequests
		}
	} = globalConfiguration;

	if (!Object.keys(params.claims ?? {}).length) {
		params.claims = undefined;
	}

	if (params.registration !== undefined) {
		throw new NotSupportedError('Registration is not supported');
	} else if (
		(params.web_message_uri !== undefined ||
			params.response_mode?.includes('web_message')) &&
		!webMessageResponseMode.enabled
	) {
		const error = new NotSupportedError(
			'Web Message Response Mode is not supported'
		);
		if (params.response_mode?.includes('web_message')) {
			error.allow_redirect = false;
		}
		throw error;
	} else if (params.claims !== undefined && !claimsParameter.enabled) {
		throw new NotSupportedError('Claims Parameter is not supported');
	} else if (params.resource !== undefined && !resourceIndicators.enabled) {
		throw new NotSupportedError('Resource Indicators is not supported');
	} else if (
		params.authorization_details !== undefined &&
		!richAuthorizationRequests.enabled
	) {
		throw new NotSupportedError('Rich Authorization Requests is not supported');
	} else if (params.dpop_jkt !== undefined && !dPoP.enabled) {
		throw new NotSupportedError('DPoP JWK Thumbprint is not supported');
	} else if (params.request !== undefined && !requestObjects.enabled) {
		throw new NotSupportedError('Request Object is not supported');
	} else if (
		params.request_uri !== undefined &&
		pushedAuthorizationRequests.enabled
	) {
		// For Authorization endpoint only
		throw new NotSupportedError('Request URI is not supported');
	}

	authorizationPKCE(params);
}
