/*
 * An application of a project that has no address of its own, so everything it does happens at the root. Declared
 * here rather than seeded by the spec, because the harness builds a sign-in's grant from this list and the case
 * has to reach a code without stopping at a consent prompt.
 */

export const clients = [
	{
		clientId: 'quiet-app',
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: ['https://quiet.example.com/cb'],
		token_endpoint_auth_method: 'none',
		'consent.require': false
	}
];

export const ApplicationConfig = {
	'introspection.enabled': true
};
