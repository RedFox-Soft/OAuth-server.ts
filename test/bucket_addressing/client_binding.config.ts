/*
 * Two kinds of client, because the binding has two halves and each needs a client only it can refuse.
 *
 * `acme-app` belongs to a project with its own address, so the client-level check refuses it anywhere else
 * before a grant runs. `shared-root-app` and `root-app` belong to no project: the client-level check lets them
 * through everywhere, which leaves the artefact a code or refresh token records — and, for client credentials,
 * the project's membership — as the only thing that can refuse them at the wrong issuer.
 */

export const clients = [
	{
		clientId: 'acme-app',
		clientSecret: 'acme-secret',
		token_endpoint_auth_method: 'client_secret_basic',
		grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
		responseTypes: ['code'],
		redirectUris: ['https://acme.example.com/cb'],
		'consent.require': false
	},
	{
		clientId: 'root-app',
		clientSecret: 'root-secret',
		token_endpoint_auth_method: 'client_secret_basic',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'shared-root-app',
		clientSecret: 'shared-secret',
		token_endpoint_auth_method: 'client_secret_basic',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://shared.example.com/cb'],
		'consent.require': false
	}
];

export const ApplicationConfig = {
	'clientCredentials.enabled': true,
	'introspection.enabled': true,
	'revocation.enabled': true,
	'par.enabled': true
};
