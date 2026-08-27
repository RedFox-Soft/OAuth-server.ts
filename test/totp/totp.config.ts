import getConfig from '../default.config.js';

const config = getConfig();

/*
 * One client per bucket state, so a spec never has to mutate a bucket another spec is using — the
 * arrangement test/interaction_ui/pages.config.ts settled on for the same reason. The buckets
 * themselves are seeded per group in each spec's beforeAll, because their flags are what
 * distinguishes the groups.
 */
export const clients = [
	{
		clientId: 'totp-required-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/totp-required/callback']
	},
	{
		clientId: 'totp-optional-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/totp-optional/callback']
	},
	{
		clientId: 'totp-migrate-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/totp-migrate/callback']
	},
	{
		clientId: 'totp-admin-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/totp-admin/callback']
	}
];

export default {
	config
};
