import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'clientCredentials.enabled': true,
	scopes: ['api:read', 'api:write']
};

export const client = {
	clientId: 'client',
	clientSecret: 'secret',
	grantTypes: ['authorization_code', 'client_credentials'],
	responseTypes: ['code'],
	redirectUris: ['https://client.example.com/cb'],
	scope: 'api:read'
};

export default {
	config
};
