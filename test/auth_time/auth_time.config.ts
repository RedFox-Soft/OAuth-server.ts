import getConfig from '../default.config.js';

const config = getConfig();
config.features = {
	claimsParameter: { enabled: true }
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			token_endpoint_auth_method: 'none',
			responseTypes: ['code'],
			grant_types: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-with-require_auth_time',
			token_endpoint_auth_method: 'none',
			responseTypes: ['code'],
			grant_types: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb'],
			require_auth_time: true
		},
		{
			clientId: 'client-with-default_max_age',
			token_endpoint_auth_method: 'none',
			responseTypes: ['code'],
			grant_types: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb'],
			default_max_age: 999
		},
		{
			clientId: 'client-with-default_max_age-zero',
			token_endpoint_auth_method: 'none',
			responseTypes: ['code'],
			grant_types: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb'],
			default_max_age: 0
		}
	]
};
