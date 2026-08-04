import getConfig from '../default.config.js';

const config = getConfig();

// Three clients: one routed to this suite's own bucket, one routed to a second bucket (so the cross-bucket
// case is real routing rather than a simulation), and the reserved console client, whose bucket the
// self-service flow must refuse outright.
export const clients = [
	// The reserved console client, so the admin-bucket refusal can be driven the way a real request would
	// reach it: resolveBucketForClient maps this client id straight to the admin bucket.
	{
		clientId: 'admin-panel',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/admin/callback']
	},
	{
		clientId: 'reset-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/reset/callback']
	},
	{
		clientId: 'reset-other-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/reset-other/callback']
	}
];

export default {
	config
};
