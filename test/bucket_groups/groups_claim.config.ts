import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The `groups` claim end to end: userinfo where scope claims are released, introspection where a resource
 * server asks about an opaque token, and refresh because a membership change has to show in the next token.
 * The shared test claim set is kept — `groups` is built in and must appear beside it whatever it holds.
 */
export const ApplicationConfig = {
	'introspection.enabled': true,
	'userinfo.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
