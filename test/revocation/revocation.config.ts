import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	revocation: { enabled: true },
	clientCredentials: { enabled: true }
});

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client2',
			clientSecret: 'secret',
			redirectUris: ['https://client2.example.com/cb']
		}
	]
};
