import getConfig from '../default.config.js';

/* A machine token is how a declared API's audience reaches a token here, so client credentials are on. */
export const ApplicationConfig = {
	...getConfig(),
	'clientCredentials.enabled': true
};

export const clients = [
	{
		clientId: 'conn-service',
		clientSecret: 'conn-service-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default {
	config: getConfig()
};
