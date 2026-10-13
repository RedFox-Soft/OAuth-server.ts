import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Two applications that differ only in whether an administrator said they cope with partial access, both
 * able to hold refresh tokens and to name a declared MCP server. `billing` is a scope of the instance's own,
 * and one detail type lets a request carry authorization details beside its checkboxes.
 */
export const MCP = 'https://mcp.acme.test/mcp';
export const PAYMENT = 'https://scheme.example/payment';

export const ApplicationConfig = {
	scopes: ['openid', 'offline_access', 'billing'],
	'claimsParameter.enabled': true,
	'resourceIndicators.enabled': true,
	'richAuthorizationRequests.enabled': true,
	'richAuthorizationRequests.types': {
		[PAYMENT]: {
			label: 'Initiate a payment',
			fields: { actions: { required: true, allowed: ['initiate'] } }
		}
	}
};

const app = {
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code', 'refresh_token'],
	responseTypes: ['code'],
	authorization_details_types: [PAYMENT]
};

export const clients = [
	{
		...app,
		clientId: 'partial-app',
		client_name: 'Acme Assistant',
		redirectUris: ['https://assistant.acme.test/cb'],
		'consent.partial': true
	},
	{
		...app,
		clientId: 'plain-app',
		client_name: 'Acme Reports',
		redirectUris: ['https://reports.acme.test/cb']
	}
];

export default {
	config
};
