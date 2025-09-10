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
			grant_types: ['authorization_code'],
			response_types: ['code', 'none'],
			redirect_uris: ['https://client.example.com'],
			token_endpoint_auth_method: 'none'
		},
		{
			clientId: 'client-encrypted',
			client_secret: 'secret',
			grant_types: ['authorization_code'],
			response_types: ['code', 'none'],
			redirect_uris: ['https://client.example.com'],
			authorization_encrypted_response_alg: 'A128KW'
		},
		{
			clientId: 'client-expired',
			client_secret: 'secret',
			client_secret_expires_at: 1,
			grant_types: ['authorization_code'],
			response_types: ['code', 'none'],
			redirect_uris: ['https://client.example.com'],
			authorization_signed_response_alg: 'HS256'
		}
	]
};
