import { MCP_RESOURCE } from './consts.js';

/*
 * The resource-server descriptor for this server's own MCP endpoint.
 *
 * Needed because `lib/addon/resources.ts` ships `getResourceServerInfo` as a `mustChange` stub that
 * *throws* `InvalidTarget`, while `resourceIndicators.enabled` defaults to true. Without a built-in
 * answer for MCP_RESOURCE, `resource=<issuer>/mcp` fails at the token endpoint, no audience-bound
 * token can ever be minted, and the whole authorization design for `/mcp` is unreachable on a
 * deployment that has not written an override. That would break the requirement that self-hosted and
 * cloud-managed instances behave identically without configuration.
 *
 * `accessTokenFormat` is deliberately `opaque`. An MCP access token is presented only back to this
 * server, which resolves it from storage — so a JWT would add a signature nobody verifies, publish the
 * administrator's account id to anything that sees the token, and make revocation advisory rather than
 * immediate. Opaque keeps revocation instant, which matters for a credential that carries
 * administrative authority.
 *
 * `scope` is 'openid' alone: the tool surface takes its authority from the administrator's roles, not
 * from scopes, so there is no scope here for an agent to ask for and nothing a wider scope would grant.
 */
export const MCP_RESOURCE_SERVER = {
	audience: MCP_RESOURCE,
	scope: 'openid',
	accessTokenFormat: 'opaque' as const
};

export function isMcpResource(identifier: unknown): boolean {
	return identifier === MCP_RESOURCE;
}
