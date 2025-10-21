import getConfig from '../default.config.js';

const config = getConfig();

config.features.deviceFlow = { enabled: true };
config.issueRefreshToken = (ctx, client) =>
	client.grantTypeAllowed('refresh_token');

export default {
	config,
	clients: [
		{
			clientId: 'client',
			responseTypes: ['code'],
			grant_types: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			scope: 'openid'
		},
		{
			clientId: 'client-refresh',
			responseTypes: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			scope: 'openid'
		},
		{
			clientId: 'client-offline',
			responseTypes: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			scope: 'openid offline_access'
		}
	]
};
