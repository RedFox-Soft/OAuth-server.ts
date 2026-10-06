import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Back-channel logout is on because ending a user's access has to tell the relying parties, and
 * introspection because a resource server asking about a token is how an ended access token shows. The
 * shared test claim set (which maps `profile` and `phone`) is kept because the profile claims are released
 * through exactly that mapping.
 */
export const ApplicationConfig = {
	'backchannelLogout.enabled': true,
	'introspection.enabled': true,
	'userinfo.enabled': true
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
	},
	{
		clientId: 'second-client',
		clientSecret: 'secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://second-client.example.com/cb'],
		backchannel_logout_uri:
			'https://second-client.example.com/backchannel_logout',
		backchannel_logout_session_required: true
	}
];

export default {
	config
};
