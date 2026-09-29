/*
 * Every signed response the server produces, switched on at once, because what is under test is the
 * one property they share — whose issuer they carry — and a config per response would be four copies
 * of the same fixture drifting apart.
 */

export const clients = [
	{
		clientId: 'default-app',
		clientSecret: 'default-secret',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://default.example.com/cb'],
		token_endpoint_auth_method: 'none'
	}
];

/* The bucket's own client, seeded into the bucket by the spec. */
export const acmeClient = {
	token_endpoint_auth_method: 'client_secret_post',
	grantTypes: ['authorization_code'],
	responseTypes: ['code'],
	redirectUris: ['https://acme-signed.example.com/cb'],
	userinfo_signed_response_alg: 'RS256',
	backchannel_logout_uri: 'https://acme-signed.example.com/backchannel',
	'consent.require': false
};

export const ApplicationConfig = {
	'introspection.enabled': true,
	'jwtIntrospection.enabled': true,
	'jwtUserinfo.enabled': true,
	'responseMode.jwt.enabled': true,
	'backchannelLogout.enabled': true
};
