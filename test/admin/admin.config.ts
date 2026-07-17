import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	clients: [
		{
			clientId: 'admin-panel',
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['http://e.ly/admin/callback']
		},
		{
			clientId: 'regular-app',
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['http://e.ly/regular/callback']
		}
	]
};
