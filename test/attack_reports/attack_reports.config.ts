import getConfig from '../default.config.js';

const config = getConfig();

/*
 * What the six signals need: SCIM and MCP served, client credentials so a confidential client has a secret to
 * get wrong, and a mail limit of three so refused mail requests are among those counted.
 *
 * The rate limit is off. The login, token, forgot-password and TOTP routes are in its strict class, and so is
 * the failed-credential charge SCIM uses, so a low limit here would turn ten wrong passwords into floods and
 * bad SCIM tokens into 429s. Only the flood case turns it on (`withRateLimit`).
 */
export const ApplicationConfig = {
	'rateLimit.enabled': false,
	'scim.enabled': true,
	'mcp.enabled': true,
	'clientCredentials.enabled': true,
	'errorStore.enabled': true,
	'mail.requestsPerCallerPerHour': 3,
	'clientAddress.source': 'automatic',
	'attackReports.enabled': true,
	scopes: ['api:read']
};

export const clients = [
	{
		clientId: 'attack-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/attack/callback']
	},
	{
		clientId: 'attack-machine',
		clientSecret: 'the-right-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: [],
		scope: 'api:read'
	}
];

export default {
	config
};
