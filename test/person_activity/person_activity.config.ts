import getConfig from '../default.config.js';

/*
 * A person's activity (specs/133). The rate limit is off because the cases sign one person in and out of one
 * address many times; the administrative MCP endpoint is on because an agent reads the activity too. The caller's
 * address is the connection's, stated per request through the test peer header.
 */
export const ApplicationConfig = {
	'rateLimit.enabled': false,
	'mcp.enabled': true,
	'clientAddress.source': 'direct'
};

export const clients = [
	{
		clientId: 'activity-app',
		client_name: 'Acme web',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/activity/callback'],
		'consent.require': false
	},
	{
		clientId: 'activity-billing',
		client_name: 'Billing',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/billing/callback'],
		'consent.require': false,
		'signIn.requireCode': true
	},
	/* The console's own client, which signs administrators in to the administrators' project. */
	{
		clientId: 'admin-panel',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/admin/callback'],
		'consent.require': false
	}
];

export default {
	config: getConfig()
};
