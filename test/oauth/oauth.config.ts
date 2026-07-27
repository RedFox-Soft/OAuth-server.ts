import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'claimsParameter.enabled': true,
	'deviceFlow.enabled': true,
	scopes: ['openid', 'offline_access', 'api:read'],
	// Explicitly empty: this OAuth-only suite opts out of the shared test claim set that
	// bootstrap applies when a config declares no `claims` of its own.
	claims: {}
};

export const client = {
	clientId: 'client',
	token_endpoint_auth_method: 'none',
	grantTypes: [
		'authorization_code',
		'refresh_token',
		'urn:ietf:params:oauth:grant-type:device_code'
	],
	responseTypes: ['code', 'none'],
	redirectUris: ['https://client.example.com/cb']
};

export default {
	config
};
