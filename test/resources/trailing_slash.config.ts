import getConfig from '../default.config.js';

/*
 * A machine client of its own: the project store outlives a spec file, and a client held by two
 * specs' projects would belong to whichever ran first.
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
