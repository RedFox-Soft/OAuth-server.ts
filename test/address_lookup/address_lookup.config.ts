import getConfig from '../default.config.js';

/*
 * The network owner and location of a person's addresses (specs/136), on a server as it is after an upgrade with
 * default settings, so activity recording, lookups and usage reporting are on by default and not pinned here (a setting
 * named here is not the one a super administrator saves). The rest is the person's activity
 * configuration (specs/133), whose helpers these cases sign people in with: the rate limit off for repeated sign-ins
 * from one address, the administrative MCP endpoint on for the agent's read, the caller's address the connection's.
 * The error store is on so that "a failed call leaves no error record" is a claim about a store that would record.
 */
export const ApplicationConfig = {
	'rateLimit.enabled': false,
	'mcp.enabled': true,
	'clientAddress.source': 'direct',
	'errorStore.enabled': true
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
