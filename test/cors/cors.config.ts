import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'clientCredentials.enabled': true,
	'introspection.enabled': true,
	'revocation.enabled': true,
	'deviceFlow.enabled': true
};

export default {
	config,
	client: {
		clientId: 'client',
		grantTypes: [
			'client_credentials',
			'urn:ietf:params:oauth:grant-type:device_code'
		],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none'
	}
};
