import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Two clients that skip consent. The spec puts `tenant-app` in a tenant's bucket and leaves
 * `default-app` an application of the default bucket, which reaches the tenant's bucket through a
 * resource that bucket declared. Both then sign the same person of the same bucket in; the only
 * difference is which bucket the application belongs to.
 */
export const clients = [
	{
		clientId: 'tenant-app',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://tenant.example.com/cb'],
		'consent.require': false
	},
	{
		clientId: 'default-app',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://default.example.com/cb'],
		'consent.require': false
	}
];

export default {
	config
};
