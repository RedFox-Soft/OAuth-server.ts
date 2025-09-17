import getConfig from '../default.config.js';

const config = getConfig();

config.allowOmittingSingleRegisteredRedirectUri = false;

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
			redirectUris: [
				'https://client.example.com/cb',
				'https://client.example.com/cb2'
			]
		},
		{
			clientId: 'client2',
			clientSecret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://client.example.com/cb3']
		}
	]
};
