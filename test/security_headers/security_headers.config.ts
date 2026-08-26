import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Every capability the sweep touches is switched on, because the contract under test is "every
 * response, whatever it is" — a flag left off silently removes a route from the sweep rather than
 * failing it, which is the one failure mode this suite exists to prevent.
 *
 * The gate-refusal case is the exception and turns a flag off deliberately, per case.
 */
export const ApplicationConfig = {
	'par.enabled': true,
	'introspection.enabled': true,
	'revocation.enabled': true,
	'registration.enabled': true,
	'registrationManagement.enabled': true,
	'deviceFlow.enabled': true,
	'ciba.enabled': true,
	'userinfo.enabled': true,
	'rpInitiatedLogout.enabled': true,
	'mcp.enabled': true,
	'federation.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: [
			'authorization_code',
			'refresh_token',
			'urn:ietf:params:oauth:grant-type:device_code'
		],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
