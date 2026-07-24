import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	introspection: { enabled: true },
	revocation: { enabled: true }
});

export const clients = [
	{
		clientId: 'client',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://rp.example.com/cb'],
		token_endpoint_auth_method: 'none'
	}
];

export default {
	config
};
