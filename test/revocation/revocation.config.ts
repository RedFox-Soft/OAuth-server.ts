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
			client_secret: 'secret',
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client2',
			client_secret: 'secret',
			redirect_uris: ['https://client2.example.com/cb']
		}
	]
};
