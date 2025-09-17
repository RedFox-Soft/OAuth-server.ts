import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb']
		}
	]
};
