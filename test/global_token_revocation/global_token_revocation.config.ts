import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The endpoint is on; back-channel logout because ending a user's access has to tell the relying parties;
 * introspection because a resource server asking about a token is how an ended access token shows.
 */
export const ApplicationConfig = {
	'globalTokenRevocation.enabled': true,
	'backchannelLogout.enabled': true,
	'introspection.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb'],
		backchannel_logout_uri: 'https://client.example.com/backchannel_logout',
		backchannel_logout_session_required: true
	}
];

export default {
	config
};
