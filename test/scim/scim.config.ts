import getConfig from '../default.config.js';

const config = getConfig();

/*
 * SCIM on, and the capabilities a provisioned user's life touches: client credentials (a connection's key
 * or secret credential obtains its token through that grant), federation (a provisioned user signs in through
 * it), back-channel logout and introspection (a SCIM deactivation must end access the way an administrator's
 * does, and introspection is where an ended access token shows).
 */
export const ApplicationConfig = {
	'scim.enabled': true,
	'clientCredentials.enabled': true,
	'federation.enabled': true,
	'backchannelLogout.enabled': true,
	'introspection.enabled': true,
	'userinfo.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
