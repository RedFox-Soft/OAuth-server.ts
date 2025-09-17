import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	registrationManagement: {
		enabled: true,
		rotateRegistrationAccessToken: false
	},
	registration: { enabled: true }
});

export default {
	config,
	client: {
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	}
};
