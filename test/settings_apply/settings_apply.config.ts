import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Deliberately no `ApplicationConfig` export: these specs prove that a setting an administrator saves
 * reaches the running server, so they must start from the values a deployment actually ships with and
 * move one of them through the management API. A baseline of their own would prove the harness.
 */

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	},
	/*
	 * Carries a metadata field the client schema only recognises while JWT introspection is on, which
	 * is how a case can tell a client interpreted under the settings in force from one interpreted
	 * under the settings that were in force when it was last resolved.
	 */
	{
		clientId: 'introspector',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb'],
		introspectionSignedResponseAlg: 'RS256'
	}
];

export default {
	config
};
