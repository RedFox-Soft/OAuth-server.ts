import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'registration.enabled': true
};

export default {
	config,
	client: {
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	}
};
