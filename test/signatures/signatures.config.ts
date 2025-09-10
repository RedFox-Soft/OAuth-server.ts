import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	clients: [
		{
			clientId: 'client-sig-none',
			client_secret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code'],
			id_token_signed_response_alg: 'none',
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-sig-HS256',
			client_secret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code'],
			id_token_signed_response_alg: 'HS256',
			redirect_uris: ['https://client.example.com/cb']
		}
	]
};
