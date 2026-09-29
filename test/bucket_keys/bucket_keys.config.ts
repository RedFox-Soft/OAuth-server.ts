import getConfig from '../default.config.js';

/*
 * Two tenants with issuers of their own — one by path, one by hostname — each with a machine client.
 * Client credentials is the shortest path to a signed token for a bucket, and a declared resource with
 * the default format is what makes that token a JWT.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientCredentials.enabled': true
};

/*
 * One pair per spec file: the project store outlives a file, and a client held by two files' projects
 * would belong to whichever ran first.
 */
export const clients = [
	{
		clientId: 'iso-path-machine',
		clientSecret: 'iso-path-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'iso-host-machine',
		clientSecret: 'iso-host-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'ep-path-machine',
		clientSecret: 'ep-path-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'ep-host-machine',
		clientSecret: 'ep-host-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'mgmt-path-machine',
		clientSecret: 'mgmt-path-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'first-path-machine',
		clientSecret: 'first-path-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default { config: getConfig() };
