import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'dpop.enabled': true,
	'dpop.nonceSecret': Buffer.alloc(32, 0)
};

/*
 * No `rotateRefreshToken` override: the default is what decides that a browser application's tokens
 * rotate on every use, and that rule is part of what is under test.
 */
export const clients = [
	{
		clientId: 'spa',
		applicationType: 'web',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://spa.example.com/cb']
	},
	{
		clientId: 'backend',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://backend.example.com/cb']
	}
];

export default {
	config
};
