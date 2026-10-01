import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The claims parameter is on so one case can ask for `amr` through it — and be answered, never
 * refused. The device flow is on for the device-grant case. Context values are renamed away from the
 * shipped defaults for the reason test/acr/acr.config.ts gives.
 */
export const ApplicationConfig = {
	'claimsParameter.enabled': true,
	'deviceFlow.enabled': true,
	acrValues: {
		password: 'urn:example:acr:pwd',
		multi_factor: 'urn:example:acr:mfa',
		federated: 'urn:example:acr:federated'
	}
};

/*
 * One client per bucket state, so no spec mutates a bucket another is using. `amr-mfa-app` and
 * `amr-mfa-second-app` share the bucket that demands a second factor, so the second can be signed in
 * from the session the first established. `amr-switch-app` has a bucket of its own because its case
 * turns the requirement off between two sign-ins.
 */
const browserClient = (clientId: string) => ({
	clientId,
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code', 'refresh_token'],
	responseTypes: ['code'],
	redirectUris: [`http://e.ly/${clientId}/callback`],
	'consent.require': false
});

export const clients = [
	browserClient('amr-app'),
	browserClient('amr-mfa-app'),
	browserClient('amr-mfa-second-app'),
	browserClient('amr-switch-app'),
	{
		clientId: 'amr-tv',
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
