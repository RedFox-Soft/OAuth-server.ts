import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	introspection: { enabled: true },
	jwtIntrospection: { enabled: true },
	encryption: { enabled: true }
});

export default {
	config,
	clients: [
		{
			clientId: 'client-signed',
			clientSecret: 'secret',
			introspection_signed_response_alg: 'RS256',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-HS-expired',
			clientSecret: 'secret',
			client_secret_expires_at: 1,
			token_endpoint_auth_method: 'none',
			introspection_signed_response_alg: 'HS256',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-encrypted',
			clientSecret: 'secret',
			token_endpoint_auth_method: 'none',
			introspection_encrypted_response_alg: 'A128KW',
			redirectUris: ['https://client.example.com/cb']
		}
	]
};
