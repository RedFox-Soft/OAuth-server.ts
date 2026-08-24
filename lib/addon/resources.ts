import { mustChange } from './_warn.ts';
import * as errors from '../helpers/errors.ts';
import { MCP_RESOURCE_SERVER, isMcpResource } from '../mcp/resource_server.js';

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

export async function useGrantedResource(_ctx, _model) {
	// @param ctx - koa request context
	// @param model - depending on the request's grant_type this can be either an AuthorizationCode, BackchannelAuthenticationRequest,
	//                RefreshToken, or DeviceCode model instance.
	return false;
}

export async function getResourceServerInfo(_ctx, resourceIndicator, _client) {
	// @param ctx - koa request context
	// @param resourceIndicator - resource indicator value either requested or resolved by the defaultResource helper.
	// @param client - client making the request

	/*
	 * This server's own MCP endpoint is answered here rather than left to a deployment, because it is
	 * not a deployment's resource: it identifies an endpoint this server serves, and an operator who
	 * could configure it could only get it wrong. Without this arm the stub below would throw for
	 * `resource=<issuer>/mcp`, so no audience-bound token could be minted and the administrative MCP
	 * surface would be unreachable until someone wrote an override — a configuration burden that would
	 * also make self-hosted and cloud-managed deployments differ.
	 *
	 * A deployment override still wins for every other indicator, because the registry resolves this
	 * whole function; only the MCP identifier is claimed.
	 */
	if (isMcpResource(resourceIndicator)) {
		return MCP_RESOURCE_SERVER;
	}

	mustChange(
		'features.resourceIndicators.getResourceServerInfo',
		'to provide details about the Resource Server identified by the Resource Indicator'
	);
	throw new errors.InvalidTarget();
}
