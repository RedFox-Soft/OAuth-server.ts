import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	clients: [
		{
			clientId: 'client',
			response_types: ['code'],
			grant_types: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none'
		},
		{
			clientId: 'client-hmac',
			clientSecret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			id_token_signed_response_alg: 'HS256'
		}
	]
};
