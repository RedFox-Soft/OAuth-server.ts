import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'clientCredentials.enabled': true,
	'deviceFlow.enabled': true
};

export const client = {
	clientId: 'client',
	token_endpoint_auth_method: 'none',
	grantTypes: [
		'authorization_code',
		'refresh_token',
		'urn:ietf:params:oauth:grant-type:device_code'
	],
	responseTypes: ['code'],
	redirectUris: ['https://rp.example.com/cb']
};

export const MACHINE_SECRET = 'dynamic-ttl-machine-secret-0123456789';

/* client_credentials needs a client that authenticates (lib/consts/confidential_grants.ts). */
export const clients = [
	client,
	{
		clientId: 'machine',
		token_endpoint_auth_method: 'client_secret_post',
		clientSecret: MACHINE_SECRET,
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default {
	config
};
