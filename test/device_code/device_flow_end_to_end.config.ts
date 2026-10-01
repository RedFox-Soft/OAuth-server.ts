import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Its own config rather than the area's: resource indicators and authentication contexts change what
 * the other device specs' requests mean, and those specs were written without them.
 */
export const ApplicationConfig = {
	'deviceFlow.enabled': true,
	'claimsParameter.enabled': true,
	'resourceIndicators.enabled': true,
	'errorStore.enabled': true,
	'rpInitiatedLogout.enabled': false,
	acrValues: {
		password: 'urn:example:acr:pwd',
		multi_factor: 'urn:example:acr:mfa',
		federated: 'urn:example:acr:federated'
	}
};

export const AUDIENCE = 'https://api.example.com/device';
export const MFA = 'urn:example:acr:mfa';

export const clients = [
	{
		clientId: 'tv',
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
