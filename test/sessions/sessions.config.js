import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	clients: [
		{
			client_id: 'client',
			client_secret: 'secret',
			redirect_uris: ['https://client.example.com/cb']
		}
	]
};
