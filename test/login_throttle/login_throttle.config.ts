import getConfig from '../default.config.js';

const config = getConfig();

/*
 * One client per bucket state, so a spec never has to mutate a bucket another spec is using — the
 * arrangement test/totp/totp.config.ts settled on for the same reason. The buckets themselves are
 * seeded per group in the spec's beforeAll, because their flags are what distinguishes the groups.
 *
 * Two are needed rather than one: FR-025 makes the escalation ceiling depend on whether the bucket
 * requires a second factor, so the flat curve and the growing one are properties of different
 * buckets and cannot be exercised through a single client.
 */
export const clients = [
	{
		clientId: 'throttle-password-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/throttle-password/callback']
	},
	{
		clientId: 'throttle-second-factor-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/throttle-second-factor/callback']
	}
];

export default {
	config
};
