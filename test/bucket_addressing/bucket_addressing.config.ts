/*
 * The addressing area needs both clients declared here rather than seeded by the fixture, because the
 * harness builds a sign-in's grants from this list: a flow that has to reach a code — which is where
 * RFC 9207's `iss` appears — cannot stop at a consent prompt.
 */

export const clients = [
	{
		clientId: 'default-app',
		clientSecret: 'default-secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://default.example.com/cb'],
		token_endpoint_auth_method: 'none'
	},
	{
		clientId: 'acme-app',
		clientSecret: 'acme-secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://acme.example.com/cb'],
		token_endpoint_auth_method: 'none',
		/* So a sign-in through the interaction screens reaches a code in one step: what is under test is
		 * the issuer the resumed request carries, not the consent prompt. */
		'consent.require': false
	}
];

export const ApplicationConfig = {
	'backchannelLogout.enabled': true,
	/* RFC 7662's `active` semantics are what bind a token to the bucket that issued it, so the area
	 * that proves that binding has to have the endpoint switched on. */
	'introspection.enabled': true
};
