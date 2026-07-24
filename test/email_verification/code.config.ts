import getConfig from '../default.config.js';

const config = getConfig();

export const clients = [
	{
		clientId: 'verify-code-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/verify-code/callback']
	}
];

export default {
	config
};
