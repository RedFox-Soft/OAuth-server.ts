import { globalConfiguration } from 'lib/globalConfiguration.js';
import { NotSupportedError } from 'lib/helpers/errors.js';
import { ApplicationConfig } from 'lib/configs/application.js';

export function featureVerification(params: Record<string, unknown>) {
	const {
		features: {
			claimsParameter,
			dPoP,
			resourceIndicators,
			richAuthorizationRequests,
			webMessageResponseMode,
			requestObjects
		}
	} = globalConfiguration;

	if (!Object.keys(params.claims ?? {}).length) {
		delete params.claims;
	}

	const isWebMessageResponseMode =
		typeof params.response_mode === 'string' &&
		params.response_mode.includes('web_message');
	if (
		(params.web_message_uri !== undefined || isWebMessageResponseMode) &&
		!webMessageResponseMode.enabled
	) {
		const error = new NotSupportedError(
			'Web Message Response Mode is not supported'
		);
		if (isWebMessageResponseMode) {
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
		!ApplicationConfig['par.enabled']
	) {
		// For Authorization endpoint only
		throw new NotSupportedError('Request URI is not supported');
	}
}
