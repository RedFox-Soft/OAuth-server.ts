import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Every surface a deleted principal's credentials could still be accepted at has to be reachable, or the
 * negatives prove nothing: introspection and userinfo consume access tokens, refresh_token consumes
 * refresh tokens, client_credentials and registration management each own an area no grant walk reaches.
 */
export const ApplicationConfig = {
	'introspection.enabled': true,
	'revocation.enabled': true,
	'clientCredentials.enabled': true,
	'refreshToken.enabled': true,
	'registration.enabled': true,
	'registrationManagement.enabled': true,
	'deviceFlow.enabled': true,
	'ciba.enabled': true
};

export const clients = [
	{
		clientId: 'doomed',
		clientSecret: 'secret',
		grantTypes: [
			'authorization_code',
			'refresh_token',
			'client_credentials',
			'urn:ietf:params:oauth:grant-type:device_code'
		],
		responseTypes: ['code'],
		redirectUris: ['https://doomed.example.com/cb']
	},
	{
		clientId: 'bystander',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://bystander.example.com/cb']
	}
];

export default {
	config
};
