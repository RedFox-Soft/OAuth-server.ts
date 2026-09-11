import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'par.enabled': true,
	'deviceFlow.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://rp.example.com/cb']
	},
	{
		clientId: 'device-client',
		grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		applicationType: 'native'
	}
];

export default {
	config
};
