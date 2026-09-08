import getConfig from '../default.config.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';

/*
 * The administrative MCP plane reached by a client identified with a document it hosts.
 *
 * Both capabilities on, which is the configuration this path actually requires and which
 * `mcp.config.ts` deliberately does not have — that harness seeds a stored client, so it never
 * exercises document retrieval at all.
 */
export const ApplicationConfig = {
	...getConfig(),
	'mcp.enabled': true,
	'clientIdMetadataDocument.enabled': true
};

/* The reserved client, so the spec can assert it keeps working alongside the document path. */
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
