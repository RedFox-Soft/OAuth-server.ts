import getConfig from '../default.config.js';

const config = getConfig();

/*
 * A person's own two-step verification (specs/126). One application signs people in to the default bucket at the
 * root; the specs give that bucket the settings each case needs (the requirement, self-service, password sign-in) and
 * configure mail, which the mailed link depends on.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'offline_access']
};

export const clients = [
	{
		clientId: 'two-step-app',
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
