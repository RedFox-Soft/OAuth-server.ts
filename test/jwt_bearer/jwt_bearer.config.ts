import getConfig from '../default.config.js';

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

/*
 * Harness for the general JWT bearer grant (specs/108 story 4): plain assertions about a person from a
 * provider the project trusts for them. `migrator` is the application the trust names; `bystander` holds the
 * grant but is not named.
 */
export const ApplicationConfig = {
	...getConfig(),
	'jwtBearer.enabled': true,
	'federation.enabled': true
};

export const clients = [
	{
		clientId: 'migrator',
		clientSecret: 'migrator-secret',
		grantTypes: [JWT_BEARER],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'bystander',
		clientSecret: 'bystander-secret',
		grantTypes: [JWT_BEARER],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'no-grant',
		clientSecret: 'no-grant-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'spa',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', JWT_BEARER],
		responseTypes: ['code'],
		redirectUris: ['https://spa.example.com/cb']
	}
];

export default {
	config: getConfig()
};
