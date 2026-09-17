import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Federation is off by default, and this suite is the one place it must be on. Declared as its own export
 * rather than assigned onto `config`, which is how every other suite raises a flag (test/rar/rar.config.ts,
 * test/cors/cors.config.ts): `getConfig()`'s return type describes only the claims block, so indexing it
 * with a flag name is an implicit `any`.
 *
 * The flag is read flat off ApplicationConfig per request rather than captured at boot, which is what lets
 * a suite drive one long-lived instance with it enabled — see lib/plugins/featureGate.ts.
 */
export const ApplicationConfig = {
	'federation.enabled': true
};

/*
 * One client per bucket the suite needs, because a client is how an interaction resolves to a bucket
 * (resolveBucketForClient). Buckets and their providers are seeded in the spec's own beforeAll rather than
 * here: each case's provider settings differ, and providers travel on the bucket document.
 */
export const clients = [
	{
		clientId: 'fed-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/fed/callback']
	},
	{
		clientId: 'fed-strict-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/fed-strict/callback']
	},
	{
		clientId: 'fed-verify-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/fed-verify/callback']
	}
];

export default {
	config
};
