import * as profile from './profile.config.ts';

/*
 * The IPSIE SL1 profile with test/amr's renamed contexts, and one browser application per project: one project
 * signs in with a password only, the other demands a second factor.
 */
export const jwks = profile.jwks;

export const ApplicationConfig = {
	...profile.ApplicationConfig,
	acrValues: {
		password: 'urn:example:acr:pwd',
		multi_factor: 'urn:example:acr:mfa',
		federated: 'urn:example:acr:federated'
	}
};

const browserClient = (clientId: string) => ({
	clientId,
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code', 'refresh_token'],
	responseTypes: ['code'],
	redirectUris: [`https://acr.example.com/${clientId}/callback`],
	'consent.require': false
});

export const clients = [
	browserClient('acr-pwd-app'),
	browserClient('acr-mfa-app')
];

export default profile.default;
