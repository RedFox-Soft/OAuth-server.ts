import getConfig from '../default.config.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';

/*
 * Harness for the administrative MCP control plane.
 *
 * `mcp.enabled` is on here and off by default everywhere else, which is deliberate on both sides: the
 * capability hands an agent administrative authority, so a deployment opts in — and so does a spec.
 */
export const ApplicationConfig = {
	...getConfig(),
	'mcp.enabled': true
};

/*
 * The reserved client an MCP agent authenticates as. Public with mandatory PKCE, and it must belong to
 * the admin project for `resolveBucketForClient` to route it to the administrator bucket — see
 * research.md D6. `ensureAdminSeed` does that wiring; this registration is what the token endpoint
 * needs to exist.
 */
export const clients = [
	{
		clientId: ADMIN_MCP_CLIENT_ID,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback']
	}
];

export default { config: getConfig() };
