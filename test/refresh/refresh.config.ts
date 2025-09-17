import getConfig from '../default.config.js';

const config = getConfig();

config.rotateRefreshToken = false;

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client2',
			clientSecret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://client.example.com/cb']
		}
	]
};
