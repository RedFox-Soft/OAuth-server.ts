import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The person's connected-applications page (specs/095) lists what each application holds and removes it, so
 * this harness holds an application of each kind the page words differently: the organization's own that asks
 * for consent, one that keeps access offline and is told when it ends, one whose consent is waived, and one
 * that registered itself under a famous name. All sign people in to the default bucket at the root; the
 * specs add a path-addressed and a host-addressed bucket of their own.
 *
 * Back-channel logout is on because ending an application's access tells it; introspection because an ended
 * access token shows there; registration because no registration may take the page client's id.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'offline_access'],
	'backchannelLogout.enabled': true,
	'introspection.enabled': true,
	'registration.enabled': true
};

export const clients = [
	{
		clientId: 'own-app',
		clientSecret: 'secret',
		client_name: 'Timesheets',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://time.acme.test/cb'],
		scope: 'openid profile email offline_access'
	},
	{
		clientId: 'offline-app',
		clientSecret: 'secret',
		client_name: 'Mail Sync',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://mail.acme.test/cb'],
		backchannel_logout_uri: 'https://mail.acme.test/backchannel_logout',
		backchannel_logout_session_required: true
	},
	{
		clientId: 'waived-app',
		clientSecret: 'secret',
		client_name: 'Intranet',
		'consent.require': false,
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://intranet.acme.test/cb']
	},
	{
		clientId: 'dcr-app',
		clientSecret: 'secret',
		client_name: '✅ Google',
		registeredDynamically: true,
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: ['https://evil.example.net/cb']
	},
	{
		clientId: 'gone-app',
		clientSecret: 'secret',
		client_name: 'Retired Tool',
		'consent.require': false,
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: ['https://retired.acme.test/cb']
	},
	{
		// Placed by a spec in a bucket with no address of its own.
		clientId: 'loose-app',
		clientSecret: 'secret',
		client_name: 'Loose Tool',
		'consent.require': false,
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: ['https://loose.acme.test/cb']
	}
];

export default {
	config
};
