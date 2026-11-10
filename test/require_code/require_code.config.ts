import getConfig from '../default.config.js';

const config = getConfig();

/*
 * An application that requires a code from an authenticator app (specs/127). Both applications sign people in to the
 * default bucket at the root; the specs give that bucket the settings each case needs (self-service, password sign-in,
 * the requirement) and configure mail, which setting a code up depends on.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'offline_access'],
	'federation.enabled': true
};

export const clients = [
	{
		clientId: 'billing',
		clientSecret: 'secret',
		client_name: 'Billing',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://billing.acme.test/cb'],
		scope: 'openid profile email offline_access',
		'consent.require': false,
		'signIn.requireCode': true
	},
	{
		clientId: 'timesheets',
		clientSecret: 'secret',
		client_name: 'Timesheets',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://time.acme.test/cb'],
		scope: 'openid profile email offline_access',
		'consent.require': false
	}
];

export default {
	config
};
