import { mustChange } from './_warn.ts';
import * as errors from '../helpers/errors.ts';

export async function defaultResource(ctx, client, oneOf) {
	// @param ctx - koa request context
	// @param client - client making the request
	// @param oneOf {string[]} - The authorization server needs to select **one** of the values provided.
	//                           Default is that the array is provided so that the request will fail.
	//                           This argument is only provided when called during
	//                           Authorization Code / Refresh Token / Device Code exchanges.

	if (oneOf) return oneOf;
	return undefined;
}

export async function useGrantedResource(ctx, model) {
	// @param ctx - koa request context
	// @param model - depending on the request's grant_type this can be either an AuthorizationCode, BackchannelAuthenticationRequest,
	//                RefreshToken, or DeviceCode model instance.
	return false;
}

export async function getResourceServerInfo(ctx, resourceIndicator, client) {
	// @param ctx - koa request context
	// @param resourceIndicator - resource indicator value either requested or resolved by the defaultResource helper.
	// @param client - client making the request
	mustChange(
		'features.resourceIndicators.getResourceServerInfo',
		'to provide details about the Resource Server identified by the Resource Indicator'
	);
	throw new errors.InvalidTarget();
}
