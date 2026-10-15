/*
 * One client per project, so a spec proving the subdomain form never reaches into a project another spec is
 * using — the arrangement test/host_buckets/host_buckets.config.ts settled on. The projects themselves are
 * seeded in each spec, because their address is what distinguishes them and a config cannot express it.
 */
export const clients = [
	{
		clientId: 'subdomain-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/subdomain/callback']
	},
	{
		clientId: 'other-subdomain-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/other-subdomain/callback']
	},
	{
		clientId: 'path-project-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/path-project/callback']
	}
];
