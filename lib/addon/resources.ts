import { mustChange } from './_warn.ts';
import * as errors from '../helpers/errors.ts';
import { MCP_RESOURCE_SERVER, isMcpResource } from '../mcp/resource_server.js';
import { resolveDeclaredResource } from '../resources/registry.js';
import { namespaceOf } from '../resources/namespace.js';
import { scimBaseUrl } from '../provisioning/addresses.js';
import {
	assertConnectionMayMint,
	isScimResourceOf,
	scimResourceServer
} from '../provisioning/token_policy.js';
import type { OIDCContext } from '../helpers/oidc_context.ts';
import type { ResourceServerInfo } from '../helpers/resource_server.ts';
import type { Client } from '../models/client.ts';
import type { AuthorizationCode } from '../models/authorization_code.ts';
import type { BackchannelAuthenticationRequest } from '../models/backchannel_authentication_request.ts';
import type { DeviceCode } from '../models/device_code.ts';
import type { RefreshToken } from '../models/refresh_token.ts';

export async function defaultResource(
	oidc: OIDCContext,
	client: Client,
	oneOf?: string | string[]
): Promise<string | string[] | undefined> {
	// @param oidc - the request context (OIDCContext)
	// @param client - client making the request
	// @param oneOf {string[]} - The authorization server needs to select **one** of the values provided.
	//                           Default is that the array is provided so that the request will fail.
	//                           This argument is only provided when called during
	//                           Authorization Code / Refresh Token / Device Code exchanges.

	if (oneOf) return oneOf;
	/*
	 * A provisioning connection's client asks for one thing only, and neither Entra nor Okta sends a
	 * `resource` — so it is supplied here, as the addressed bucket's SCIM resource. Whether this client may
	 * have it is still decided where every other request is (lib/provisioning/token_policy.ts).
	 */
	if (client.provisioningConnectionId) {
		return scimBaseUrl(oidc.bucket) ?? undefined;
	}
	return undefined;
}

export async function useGrantedResource(
	_oidc: OIDCContext,
	_model:
		| AuthorizationCode
		| BackchannelAuthenticationRequest
		| RefreshToken
		| DeviceCode
) {
	// @param oidc - the request context (OIDCContext)
	// @param model - depending on the request's grant_type this can be either an AuthorizationCode, BackchannelAuthenticationRequest,
	//                RefreshToken, or DeviceCode model instance.
	return false;
}

export async function getResourceServerInfo(
	oidc: OIDCContext,
	resourceIndicator: string,
	client: Client
): Promise<ResourceServerInfo> {
	// @param oidc - the request context (OIDCContext)
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
	/*
	 * The addressed bucket's SCIM endpoint, built in for the reason the MCP arm below is: it is an endpoint
	 * this server serves, so no deployment could declare it correctly. Only that bucket's enabled
	 * connections may hold it — any other client, on any flow, is refused here rather than handed a token a
	 * SCIM principal would then have to reject. And a connection's client holds nothing else, so for it
	 * every other indicator is refused too — first, before the MCP arm could hand it an administrative
	 * audience.
	 */
	if (
		isScimResourceOf(oidc.bucket, resourceIndicator) ||
		client.provisioningConnectionId
	) {
		await assertConnectionMayMint(client, oidc.bucket, resourceIndicator);
		return scimResourceServer(resourceIndicator);
	}

	if (isMcpResource(resourceIndicator)) {
		return MCP_RESOURCE_SERVER;
	}

	/*
	 * A resource an administrator declared in one of their projects. Second, not first: the arm above
	 * claims this server's own MCP audience, and a declaration must never be able to take it over —
	 * which is also why `${ISSUER}/mcp` is refused at declaration time rather than only here.
	 *
	 * This is what makes the capability data rather than code. Before it, an audience this server had
	 * not been compiled to know about fell to the stub below, so protecting a third-party MCP server
	 * meant writing an override in this repository.
	 *
	 * Looked up only in the namespace of the address this request arrived at: the same identifier may be
	 * declared by another tenant with an issuer of its own, and that declaration is not this one.
	 */
	const declared = await resolveDeclaredResource(
		resourceIndicator,
		namespaceOf(oidc.bucket)
	);
	if (declared) {
		return declared;
	}

	mustChange(
		'features.resourceIndicators.getResourceServerInfo',
		'to provide details about the Resource Server identified by the Resource Indicator'
	);
	throw new errors.InvalidTarget();
}
