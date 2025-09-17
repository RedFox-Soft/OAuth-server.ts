import pull from 'lodash/pull.js';
import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	requestObjects: {
		enabled: true,
		requireUriRegistration: false
	},
	claimsParameter: { enabled: true },
	deviceFlow: { enabled: true }
});

pull(config.enabledJWA.requestObjectSigningAlgValues, 'HS384');

export default {
	config,
	clients: [
		{
			clientId: 'client',
			token_endpoint_auth_method: 'none',
			clientSecret: 'secret',
			grant_types: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'authorization_code'
			],
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-requiredSignedRequestObject',
			token_endpoint_auth_method: 'none',
			require_signed_request_object: true,
			clientSecret: 'secret',
			grant_types: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'authorization_code'
			],
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-with-HS-sig',
			token_endpoint_auth_method: 'none',
			clientSecret: 'secret',
			request_object_signing_alg: 'HS256',
			grant_types: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'authorization_code'
			],
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-with-HS-sig-expired',
			client_secret_expires_at: 1,
			token_endpoint_auth_method: 'none',
			clientSecret: 'secret',
			request_object_signing_alg: 'HS256',
			grant_types: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'authorization_code'
			],
			redirectUris: ['https://client.example.com/cb']
		}
	]
};
