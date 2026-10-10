import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Every way a token is issued on an end user's behalf, so one suite can prove each one counts: the code flow
 * and its refresh, the device flow, and a sign-in through an upstream provider.
 *
 * One client per bucket a case needs, so no case mutates a bucket another is counting in. `act-app` and
 * `act-app-2` share a bucket — the same person signing in through two applications of it is one person.
 * `act-default` is in no project, so its sign-ins land in the default bucket. `admin-panel` is the
 * console's own client, which signs administrators into the administrators bucket.
 */
export const ApplicationConfig = {
	'deviceFlow.enabled': true,
	'federation.enabled': true,
	'clientCredentials.enabled': true
};

const browserClient = (clientId: string) => ({
	clientId,
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code', 'refresh_token'],
	responseTypes: ['code'],
	redirectUris: [`http://e.ly/${clientId}/callback`],
	'consent.require': false
});

export const clients = [
	browserClient('act-app'),
	browserClient('act-app-2'),
	browserClient('act-other'),
	browserClient('act-default'),
	browserClient('act-mfa'),
	browserClient('act-throttle'),
	browserClient('act-provisioned'),
	browserClient('act-fed'),
	browserClient('act-rollover'),
	{
		clientId: 'act-tv',
		grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		applicationType: 'native'
	},
	{
		clientId: 'admin-panel',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/admin/callback'],
		'consent.require': false
	},
	{
		clientId: 'act-service',
		clientSecret: 'act-service-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default {
	config
};
