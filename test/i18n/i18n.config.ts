import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	scopes: ['openid', 'offline_access'],
	'requestObjects.enabled': true,
	'par.enabled': true,
	'deviceFlow.enabled': true,
	// The property spec starts hundreds of sign-ins from one address; the limiter is proved elsewhere.
	'rateLimit.enabled': false
};

/*
 * One application of a bucket that signs people in with a password and sends no verification email, so a
 * spec can walk the whole sign-in — page, password, consent — and see which language each step speaks.
 */
export const clients = [
	{
		clientId: 'i18n-app',
		client_name: 'Acme Notes',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://notes.acme.test/cb']
	},
	{
		clientId: 'i18n-jar',
		client_name: 'Acme Notes',
		token_endpoint_auth_method: 'none',
		clientSecret: 'secret',
		'requestObject.signingAlg': 'HS256',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://notes.acme.test/cb']
	},
	{
		clientId: 'tv',
		client_name: 'Living Room TV',
		grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		applicationType: 'native'
	}
];

export default {
	config
};
