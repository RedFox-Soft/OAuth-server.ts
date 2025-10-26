import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

delete config.claims;
config.scopes = ['openid', 'offline_access', 'api:read'];
merge(config.features, {
	claimsParameter: { enabled: true },
	deviceFlow: { enabled: true }
});

export default {
	config,
	client: {
		clientId: 'client',
		token_endpoint_auth_method: 'none',
		grantTypes: [
			'authorization_code',
			'refresh_token',
			'urn:ietf:params:oauth:grant-type:device_code'
		],
		responseTypes: ['code', 'none'],
		redirectUris: ['https://client.example.com/cb']
	}
};
