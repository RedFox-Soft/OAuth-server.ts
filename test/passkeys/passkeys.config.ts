import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Signing in with a passkey (specs/139). Three projects, seeded by the specs because their address is what
 * distinguishes them: two at a path of the instance (the second only to show isolation) and one at a subdomain. Each
 * has a public client of its own; mail is configured by the specs, since adding a passkey depends on it. The context
 * values are renamed away from the shipped defaults, as in test/amr/amr.config.ts, so a case can tell them apart.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'offline_access'],
	'deviceFlow.enabled': true,
	'claimsParameter.enabled': true,
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
	redirectUris: [`https://${clientId}.apps.test/cb`],
	scope: 'openid profile email offline_access',
	'consent.require': false
});

export const clients = [
	browserClient('acme-app'),
	browserClient('beta-app'),
	browserClient('sub-app'),
	/* An app of a project with no address of its own, which signs its people in at the root (not_me.spec.ts). */
	browserClient('quiet-app'),
	/* An app of a project that requires two-step sign-in of its own (specs/127), which a passkey sign-in meets. */
	{ ...browserClient('acme-billing'), 'signIn.requireCode': true },
	{
		clientId: 'acme-tv',
		grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		applicationType: 'native'
	}
];

export default {
	config
};
