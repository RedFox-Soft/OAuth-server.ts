import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { registration: { enabled: true } });

export default {
	config,
	client: {
		clientId: 'client',
		client_secret: 'secret',
		redirect_uris: ['https://client.example.com/cb']
	}
};
