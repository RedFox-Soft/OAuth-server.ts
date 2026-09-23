import getConfig from '../default.config.js';
import { grantTypeAllowed } from 'lib/models/client.js';

const config = getConfig();

export const ApplicationConfig = {
	'deviceFlow.enabled': true
};

export const addons = {
	issueRefreshToken: (oidc, client) => grantTypeAllowed(client, 'refresh_token')
};

export const clients = [
	{
		clientId: 'client',
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: ['https://client.example.com/cb'],
		token_endpoint_auth_method: 'none',
		scope: 'openid'
	},
	{
		clientId: 'client-refresh',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb'],
		token_endpoint_auth_method: 'none',
		scope: 'openid'
	},
	{
		clientId: 'client-offline',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb'],
		token_endpoint_auth_method: 'none',
		scope: 'openid offline_access'
	}
];

export default {
	config
};
