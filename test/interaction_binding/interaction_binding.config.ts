import getConfig from '../default.config.js';

const config = getConfig();

/*
 * One client per bucket state, the arrangement test/login_throttle settled on: a password-only bucket for
 * the sign-in screen, and one requiring a second factor for the step after a correct password.
 */
export const clients = [
	{
		clientId: 'binding-password-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/binding-password/callback']
	},
	{
		clientId: 'binding-second-factor-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/binding-second-factor/callback']
	}
];

export default {
	config
};
