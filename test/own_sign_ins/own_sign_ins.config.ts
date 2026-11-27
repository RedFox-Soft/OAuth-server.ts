import getConfig from '../default.config.js';

const config = getConfig();

/*
 * A person's own recent sign-ins and signing out everywhere (specs/135). One application that keeps access offline,
 * so a refresh token and an access token exist to be ended; introspection shows an ended access token. All sign
 * people in to the default bucket at the root.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'offline_access'],
	'introspection.enabled': true
};

export const clients = [
	{
		clientId: 'own-app',
		clientSecret: 'secret',
		client_name: 'Timesheets',
		'consent.require': false,
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://time.acme.test/cb'],
		scope: 'openid profile email offline_access'
	},
	{
		clientId: 'unnamed-app',
		token_endpoint_auth_method: 'none',
		'consent.require': false,
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: ['https://unnamed.acme.test/cb'],
		scope: 'openid'
	}
];

export default {
	config
};
