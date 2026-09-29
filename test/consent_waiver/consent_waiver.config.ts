import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Two clients that skip consent, neither in a project with a bucket of its own, so both sign into the
 * default bucket. The spec puts one in a tenant's project and the other in a project of the System
 * group that owns the default bucket; the only difference is who owns the bucket they reach.
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
		clientId: 'system-app',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://system.example.com/cb'],
		'consent.require': false
	}
];

export default {
	config
};
