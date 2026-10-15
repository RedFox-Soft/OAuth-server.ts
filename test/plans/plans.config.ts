/*
 * Projects are created through the admin routes in each spec, because their plan is what the specs are about and a
 * config cannot express it. The one client is for the sign-up cases, which bind it to the project they seed.
 */
export const ApplicationConfig = {
	'federation.enabled': true
};

export const clients = [
	{
		clientId: 'plans-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/plans/callback']
	}
];
