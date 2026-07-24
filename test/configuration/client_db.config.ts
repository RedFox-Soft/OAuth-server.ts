import getConfig from '../default.config.js';

const config = getConfig();

export const clients = [
	{
		clientId: 'db-client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
