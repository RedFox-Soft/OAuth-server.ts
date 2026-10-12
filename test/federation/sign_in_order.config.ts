import getConfig from '../default.config.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';

/*
 * Federation on, so a bucket offers its providers on its sign-in page, and the administrative MCP plane on,
 * so an agent can be shown to reorder them as the console does.
 */
export const ApplicationConfig = {
	'federation.enabled': true,
	'mcp.enabled': true
};

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
