import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	encryption: { enabled: true },
	jwtResponseModes: { enabled: true }
});

export const ApplicationConfig = {
	'responseMode.jwt.enabled': true
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			grantTypes: ['authorization_code'],
			responseTypes: ['code', 'none'],
			redirectUris: ['https://client.example.com'],
			token_endpoint_auth_method: 'none'
		},
		{
			clientId: 'client-encrypted',
			clientSecret: 'secret',
			grantTypes: ['authorization_code'],
			responseTypes: ['code', 'none'],
			redirectUris: ['https://client.example.com'],
			authorization_encrypted_response_alg: 'A128KW'
		},
		{
			clientId: 'client-expired',
			clientSecret: 'secret',
			client_secret_expires_at: 1,
			grantTypes: ['authorization_code'],
			responseTypes: ['code', 'none'],
			redirectUris: ['https://client.example.com'],
			authorization_signed_response_alg: 'HS256'
		}
	]
};
