import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { clientCredentials: { enabled: true } });
config.scopes = ['api:read', 'api:write'];

export default {
	config,
	client: {
		clientId: 'client',
		clientSecret: 'secret',
		grant_types: ['authorization_code', 'client_credentials'],
		response_types: ['code'],
		redirectUris: ['https://client.example.com/cb'],
		scope: 'api:read'
	}
};
