import getConfig from '../default.config.js';

const config = getConfig();

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
