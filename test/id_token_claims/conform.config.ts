import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	claimsParameter: { enabled: true },
	jwtUserinfo: { enabled: true }
});

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
			redirectUris: ['https://client.example.com/cb'],
			userinfo_signed_response_alg: 'HS256'
		}
	]
};
