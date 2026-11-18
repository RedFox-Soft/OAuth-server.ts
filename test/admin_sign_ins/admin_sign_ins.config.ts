import getConfig from '../default.config.js';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

/*
 * Administrators' sign-ins (specs/137). The rate limit is off because the cases sign one administrator in many times
 * from one address; the administrative MCP endpoint is on because an agent reads the sign-ins too. The caller's
 * address is the connection's, stated per request through the test peer header.
 */
export const ApplicationConfig = {
	'rateLimit.enabled': false,
	'mcp.enabled': true,
	'clientAddress.source': 'direct'
};

export const clients = [
	/* The console's own client, which signs administrators in to the administrators' project. */
	{
		clientId: 'admin-panel',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/admin/callback'],
		'consent.require': false
	},
	/* An outside tool registered in the administrators' project (specs/109). */
	{
		clientId: 'admin-wiki',
		client_name: 'Ops wiki',
		bucketId: ADMIN_BUCKET_ID,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/wiki/callback'],
		'consent.require': false
	}
];

export default {
	config: getConfig()
};
