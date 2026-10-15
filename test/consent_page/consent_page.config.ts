import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The consent page decides what to say from who stands behind a client and where it sends the answer, so
 * this harness holds one client of each kind: the organization's own, another tenant's (put in a bucket
 * by the spec), two that registered themselves, a program on this computer, and an app claiming
 * a private-use scheme. `billing` is a scope of the instance's own with no standard meaning.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'offline_access', 'billing'],
	'claimsParameter.enabled': true,
	'resourceIndicators.enabled': true
};

export const MCP = 'https://mcp.acme.test/mcp';

export const clients = [
	{
		clientId: 'own-app',
		client_name: 'Acme Billing',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://billing.acme.test/cb'],
		scope: 'openid profile email phone billing offline_access'
	},
	{
		clientId: 'tenant-app',
		client_name: 'Partner Tool',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://partner.test/cb']
	},
	{
		clientId: 'self-registered',
		client_name: '✅ Google‮',
		registeredDynamically: true,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://evil.example.net/cb']
	},
	{
		clientId: 'look-alike',
		// Cyrillic А, с and е: "Acme ID" to the eye, something else to a comparison of code points.
		client_name: 'Асmе ID Support',
		registeredDynamically: true,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://lookalike.test/cb']
	},
	{
		clientId: 'local-program',
		client_name: 'Claude Code',
		registeredDynamically: true,
		applicationType: 'native',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1/callback']
	},
	{
		clientId: 'scheme-app',
		client_name: 'Acme Mobile',
		applicationType: 'native',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['com.acme.mobile:/callback']
	}
];

export default {
	config
};
