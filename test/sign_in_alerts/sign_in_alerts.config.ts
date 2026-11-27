import getConfig from '../default.config.js';

/*
 * Emails about a sign-in from a new network or browser (specs/138). The rate limit is off because the cases sign
 * people in many times from a few addresses; the administrative MCP endpoint is on because an agent reads the
 * activity. The caller's address is the connection's, stated per request through the test peer header.
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
		'consent.require': false
	},
	/* Existing clients with no client_name: must never be reported as deleted applications. */
	{
		clientId: 'unnamed-web',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://portal.acme.test/callback'],
		'consent.require': false
	},
	{
		clientId: 'unnamed-native',
		application_type: 'native',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:4321/callback'],
		'consent.require': false
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
