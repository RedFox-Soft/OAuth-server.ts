import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	clients: [
		{
			clientId: 'verify-link-app',
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['http://e.ly/verify-link/callback']
		},
		{
			clientId: 'verify-closed-app',
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['http://e.ly/verify-closed/callback']
		},
		{
			clientId: 'verify-off-app',
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['http://e.ly/verify-off/callback']
		}
	]
};
