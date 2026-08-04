import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Three clients so each bucket state gets its own, and a test never has to mutate a bucket another test
 * is using: the buckets themselves are seeded per group in the spec's beforeAll, because their flags are
 * what distinguishes the groups.
 */
export const clients = [
	{
		clientId: 'ui-verify-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/ui-verify/callback']
	},
	{
		clientId: 'ui-closed-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/ui-closed/callback']
	},
	{
		clientId: 'ui-open-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/ui-open/callback']
	}
];

export default {
	config
};
