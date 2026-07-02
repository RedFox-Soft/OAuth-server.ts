import { NotSupportedError } from 'lib/helpers/errors.js';
import { ApplicationConfig as config } from 'lib/configs/application.js';

export function featureVerification(params: Record<string, unknown>) {
	if (!Object.keys(params.claims ?? {}).length) {
		delete params.claims;
	}

	if (params.claims !== undefined && !config['claimsParameter.enabled']) {
		throw new NotSupportedError('Claims Parameter is not supported');
	} else if (
		params.resource !== undefined &&
		!config['resourceIndicators.enabled']
	) {
		throw new NotSupportedError('Resource Indicators is not supported');
	} else if (
		params.authorization_details !== undefined &&
		!config['richAuthorizationRequests.enabled']
	) {
		throw new NotSupportedError('Rich Authorization Requests is not supported');
	} else if (params.dpop_jkt !== undefined && !config['dpop.enabled']) {
		throw new NotSupportedError('DPoP JWK Thumbprint is not supported');
	} else if (
		params.request !== undefined &&
		!config['requestObjects.enabled']
	) {
		throw new NotSupportedError('Request Object is not supported');
	} else if (params.request_uri !== undefined && !config['par.enabled']) {
		// For Authorization endpoint only
		throw new NotSupportedError('Request URI is not supported');
	}
}
