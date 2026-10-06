import getConfig from '../default.config.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';

/* The administrative MCP control plane, opted into for this spec as a deployment would. */
export const ApplicationConfig = {
	...getConfig(),
	'mcp.enabled': true
};

/* The reserved client an MCP agent authenticates as; see test/mcp/confirmation_matrix.config.ts. */
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
