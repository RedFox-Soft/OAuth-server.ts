import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Both ways a client's redirect URIs can reach this server without an operator are on — dynamic
 * registration and metadata documents — beside clients an operator did create, so each case can be
 * told apart from its trusted twin by provenance alone.
 */
export const ApplicationConfig = {
	'registration.enabled': true,
	'clientIdMetadataDocument.enabled': true,
	'responseMode.jwt.enabled': true,
	'rpInitiatedLogout.enabled': false
};

export const TRUSTED_REDIRECT = 'https://client.example.com/cb';
export const URL_ID = 'https://partner.example.com/oauth/client';
export const URL_ID_REDIRECT = 'https://partner.example.com/cb';
export const UNTRUSTED_REDIRECT = 'https://evil.example/cb';

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: [TRUSTED_REDIRECT]
	},
	{
		clientId: URL_ID,
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: [URL_ID_REDIRECT]
	},
	{
		clientId: 'self-registered',
		clientSecret: 'secret',
		client_name: 'Trusted Bank',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: [UNTRUSTED_REDIRECT],
		// What the registration endpoint stores; a registrant cannot set it (test/dynamic_registration/).
		registeredDynamically: true
	}
];

export default {
	config
};
