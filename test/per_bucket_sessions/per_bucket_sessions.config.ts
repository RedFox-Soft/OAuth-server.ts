/*
 * Two buckets, which is the whole point: every other area in this suite seeds one, and nothing this
 * feature does is observable with one.
 *
 * Only the default bucket's client is declared here. The second bucket needs a bucket record, a
 * project pointing at it and a client held by that project — three writes that must happen after
 * bootstrap has cleared the adapter, so the spec files seed it with `seedBucket()` in `beforeAll`
 * and drop it with `clearSeededBuckets()` in `afterAll`.
 */

export const clients = [
	{
		clientId: 'default-app',
		clientSecret: 'default-secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://default.example.com/cb'],
		token_endpoint_auth_method: 'none'
	}
];

export const ApplicationConfig = {
	'backchannelLogout.enabled': true
};
