import getConfig from '../default.config.js';

const config = getConfig();
config.scopes = ['api:read', 'api:write'];

export const ApplicationConfig = {
	'clientCredentials.enabled': true
};

export default {
	config,
	client: {
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'client_credentials'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb'],
		scope: 'api:read'
	}
};
