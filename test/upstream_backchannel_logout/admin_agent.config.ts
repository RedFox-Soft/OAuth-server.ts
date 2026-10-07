import getConfig from '../default.config.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';

const config = getConfig();

/*
 * An agent switching a provider's back-channel logout on over MCP: the control plane is opt-in, so this spec
 * opts in; federation is on because the address the agent is handed exists only while it is.
 */
export const ApplicationConfig = {
	'mcp.enabled': true,
	'federation.enabled': true
};

/* The reserved client an MCP agent authenticates as (see test/mcp/mcp.config.ts). */
export const clients = [
	{
		clientId: ADMIN_MCP_CLIENT_ID,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback']
	}
];

export default { config };
