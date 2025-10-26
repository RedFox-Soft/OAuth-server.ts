import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	clients: [
		{
			clientId: 'client-sig-none',
			clientSecret: 'secret',
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			id_token_signed_response_alg: 'none',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-sig-HS256',
			clientSecret: 'secret',
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			id_token_signed_response_alg: 'HS256',
			redirectUris: ['https://client.example.com/cb']
		}
	]
};
