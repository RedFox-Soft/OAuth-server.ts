import getConfig from '../default.config.js';

const config = getConfig();

function allowUnregisteredClient(suffix, metadata) {
	return {
		clientId: `client-unregistered-test-${suffix}`,
		applicationType: 'web',
		token_endpoint_auth_method: 'client_secret_basic',
		clientSecret: 'secret',
		redirectUris: ['https://rp.example.com/cb'],
		...metadata
	};
}

export const ApplicationConfig = {
	'authorization.allowOmittingSingleRegisteredRedirectUri': true,
	'par.enabled': true,
	'claimsParameter.enabled': true,
	'requestObjects.enabled': true
};

export const clients = [
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
		'requestObject.signingAlg': 'HS256',
		redirectUris: ['https://rp.example.com/cb']
	},
	allowUnregisteredClient('public', { token_endpoint_auth_method: 'none' })
];

export default {
	config
};
