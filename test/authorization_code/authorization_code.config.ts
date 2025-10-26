import getConfig from '../default.config.js';

const config = getConfig();

config.allowOmittingSingleRegisteredRedirectUri = false;

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			grantTypes: ['authorization_code', 'refresh_token'],
			responseTypes: ['code'],
			redirectUris: [
				'https://client.example.com/cb',
				'https://client.example.com/cb2'
			]
		},
		{
			clientId: 'client2',
			clientSecret: 'secret',
			grantTypes: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://client.example.com/cb3']
		}
	]
};
