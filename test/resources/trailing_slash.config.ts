import getConfig from '../default.config.js';

/*
 * A machine client of its own, bound by the spec to the bucket that declares the resource.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientCredentials.enabled': true
};

export const clients = [
	{
		clientId: 'slash-machine',
		clientSecret: 'slash-machine-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default { config: getConfig() };
