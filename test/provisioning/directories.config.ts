import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import {
	ApplicationConfig as scim,
	clients as scimClients,
	default as scimDefault
} from '../scim/scim.config.ts';

/*
 * SCIM on, and the administrative MCP plane with it: the directory guidance is read by the console and by an
 * agent, and the spec proves they read the same facts.
 */
export const ApplicationConfig = {
	...scim,
	'mcp.enabled': true
};

export const clients = [
	...scimClients,
	{
		clientId: ADMIN_MCP_CLIENT_ID,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback']
	}
];

export default scimDefault;
