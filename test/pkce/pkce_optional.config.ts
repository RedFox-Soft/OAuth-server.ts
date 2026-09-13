export const ApplicationConfig = {
	'pkce.required': false,
	// The policy must hold identically at both entry points into an authorization request, so the
	// pushed endpoint has to be reachable for this instance to prove it.
	'par.enabled': true
};

/*
 * Two clients, and the difference between them is what every case in pkce_optional.spec.ts turns on.
 * The public one stays first because AuthorizationRequest defaults client_id to clients[0], and the
 * refusals are the invariant worth having as the default subject.
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
