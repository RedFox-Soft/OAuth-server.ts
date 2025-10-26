import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	jwtResponseModes: { enabled: true }
});

export default {
	config,
	clients: [
		{
			clientId: 'client',
			token_endpoint_auth_method: 'none',
			redirectUris: ['https://client.example.com/cb'],
			grantTypes: ['authorization_code'],
			scope: 'openid',
			responseTypes: ['code', 'none']
		}
	]
};
