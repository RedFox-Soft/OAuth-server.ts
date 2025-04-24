import getConfig from '../default.config.js';

const config = getConfig();

config.features.deviceFlow = { enabled: true };
config.issueRefreshToken = (ctx, client) =>
	client.grantTypeAllowed('refresh_token');

export default {
	config,
	clients: [
		{
			client_id: 'client',
			response_types: ['code'],
			grant_types: ['authorization_code'],
			redirect_uris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			scope: 'openid'
		},
		{
			client_id: 'client-refresh',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirect_uris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			scope: 'openid'
		},
		{
			client_id: 'client-offline',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirect_uris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			scope: 'openid offline_access'
		}
	]
};
