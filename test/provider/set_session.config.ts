import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	client: {
		clientId: 'client',
		client_secret: 'secret',
		redirect_uris: ['https://client.example.com/cb']
	}
};
