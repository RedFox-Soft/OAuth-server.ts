import getConfig from '../default.config.js';

/*
 * Two tenants with issuers of their own — one addressed by path, one by hostname — each with a machine
 * client, because what is under test is which tenant's declaration a token request at each address
 * reaches, and client credentials is the shortest path to a token for a named resource.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientCredentials.enabled': true
};

export const clients = [
	{
		clientId: 'acme-machine',
		clientSecret: 'acme-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'globex-machine',
		clientSecret: 'globex-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default { config: getConfig() };
