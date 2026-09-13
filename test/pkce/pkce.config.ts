import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	introspection: { enabled: true },
	revocation: { enabled: true }
});

/*
 * Order is load-bearing: AuthorizationRequest defaults client_id to clients[0], so the public client
 * stays first and every case written against it keeps meaning what it meant. The confidential client
 * is appended, never prepended.
 */
export const clients = [
	{
		clientId: 'client',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://rp.example.com/cb'],
		token_endpoint_auth_method: 'none'
	},
	{
		clientId: 'confidential-client',
		clientSecret: 'confidential-secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://confidential.example.com/cb'],
		token_endpoint_auth_method: 'client_secret_basic'
	}
];

export default {
	config
};
