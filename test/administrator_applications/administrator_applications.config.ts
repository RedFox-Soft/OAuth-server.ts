import getConfig from '../default.config.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

/*
 * Harness for applications in the Administrators project (specs/109): `ops-tool` is such an application, as a
 * super administrator registers one for an internal tool; `admin-mcp` is the seeded agent client, kept as the
 * control for what an administrators' application may not do; `portal` is an ordinary application of the
 * default project.
 */
export const ApplicationConfig = {
	...getConfig(),
	'mcp.enabled': true,
	'userinfo.enabled': true,
	// On, so a refused machine grant is refused by the client's own list rather than instance-wide.
	'clientCredentials.enabled': true
};

export const clients = [
	{
		clientId: 'ops-tool',
		clientSecret: 'ops-tool-secret',
		bucketId: ADMIN_BUCKET_ID,
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://ops.example/cb'],
		post_logout_redirect_uris: ['https://ops.example/']
	},
	{
		clientId: ADMIN_MCP_CLIENT_ID,
		bucketId: ADMIN_BUCKET_ID,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback']
	},
	{
		clientId: 'portal',
		clientSecret: 'portal-secret',
		grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
		responseTypes: ['code'],
		redirectUris: ['https://portal.example/cb']
	}
];

export default { config: getConfig() };
