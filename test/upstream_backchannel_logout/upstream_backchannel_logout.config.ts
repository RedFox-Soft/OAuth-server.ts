import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Federation on, because the receiver is a federation endpoint and a session gets its upstream origin only
 * from a federated sign-in; back-channel logout on, because ending a session has to tell the relying
 * parties; introspection, because an ended access token shows there; the error store, because a fault the
 * receiver cannot answer as a 500 must still be recorded.
 */
export const ApplicationConfig = {
	'federation.enabled': true,
	'backchannelLogout.enabled': true,
	'introspection.enabled': true,
	'errorStore.enabled': true
};

/* Two relying parties that asked to be told, so a fan-out to more than one is observable. */
export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb'],
		backchannel_logout_uri: 'https://client.example.com/backchannel_logout',
		backchannel_logout_session_required: true
	},
	{
		clientId: 'client-2',
		clientSecret: 'secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client-2.example.com/cb'],
		backchannel_logout_uri: 'https://client-2.example.com/backchannel_logout',
		backchannel_logout_session_required: true
	}
];

export default {
	config
};
