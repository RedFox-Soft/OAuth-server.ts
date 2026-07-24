import getConfig from '../default.config.js';

const config = getConfig();

export const client = {
	clientId: 'client',
	clientSecret: 'secret',
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code'],
	responseTypes: ['code'],
	redirectUris: ['https://client.example.com/cb']
};

export default {
	config
};
