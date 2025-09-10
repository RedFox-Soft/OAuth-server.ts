import getConfig from '../default.config.js';

const config = getConfig();

config.rotateRefreshToken = false;

export default {
	config,
	clients: [
		{
			clientId: 'client',
			client_secret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client2',
			client_secret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			redirect_uris: ['https://client.example.com/cb']
		}
	]
};
