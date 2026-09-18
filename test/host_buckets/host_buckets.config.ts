/*
 * One client per address form, so a spec proving the host path never has to reach into the bucket the
 * path specs are using — the arrangement test/totp/totp.config.ts settled on for the same reason. The
 * buckets themselves are seeded in each spec's beforeAll, because their address is what distinguishes
 * the groups and a config cannot express "this one has a host and that one a slug".
 */
export const clients = [
	{
		clientId: 'host-bucket-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/host-bucket/callback']
	},
	{
		clientId: 'path-bucket-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/path-bucket/callback']
	},
	{
		clientId: 'other-host-bucket-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/other-host-bucket/callback']
	}
];
