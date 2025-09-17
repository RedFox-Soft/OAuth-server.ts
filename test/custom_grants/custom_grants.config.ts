import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	client: {
		clientId: 'client',
		clientSecret: 'secret',
		grant_types: ['authorization_code'],
		response_types: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
};
