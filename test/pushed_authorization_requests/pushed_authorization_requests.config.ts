import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	claimsParameter: {
		enabled: true
	},
	requestObjects: { enabled: true }
});

function allowUnregisteredClient(suffix, metadata) {
	return {
		clientId: `client-unregistered-test-${suffix}`,
		application_type: 'web',
		token_endpoint_auth_method: 'client_secret_basic',
		clientSecret: 'secret',
		redirectUris: ['https://rp.example.com/cb'],
		...metadata
	};
}

export const ApplicationConfig = {
	'par.enabled': true
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			redirectUris: ['https://rp.example.com/cb']
		},
		{
			clientId: 'client-par-required',
			clientSecret: 'secret',
			redirectUris: ['https://rp.example.com/cb'],
			'authorization.requirePushedAuthorizationRequests': true
		},
		{
			clientId: 'client-alg-registered',
			clientSecret: 'secret',
			request_object_signing_alg: 'HS256',
			redirectUris: ['https://rp.example.com/cb']
		},
		allowUnregisteredClient('public', { token_endpoint_auth_method: 'none' })
	]
};
