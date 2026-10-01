import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Its own config rather than signin.config.ts: this case exchanges the code for tokens, so its client
 * must reach the callback without a consent step the other federation suites stop short of.
 */
export const ApplicationConfig = {
	'federation.enabled': true
};

export const clients = [
	{
		clientId: 'fed-amr-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/fed-amr/callback'],
		'consent.require': false
	}
];

export default {
	config
};
