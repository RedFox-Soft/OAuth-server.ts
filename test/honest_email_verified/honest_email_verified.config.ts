import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Two applications, each bound in the spec to a project of its own: one that does not require email verification
 * and one that does. Sign-up through each is what the cases compare.
 */
export const clients = [
	{
		clientId: 'honest-off-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/honest-off/callback']
	},
	{
		clientId: 'honest-on-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/honest-on/callback']
	}
];

export const ApplicationConfig = {
	'rateLimit.enabled': false
};

export default {
	config
};
