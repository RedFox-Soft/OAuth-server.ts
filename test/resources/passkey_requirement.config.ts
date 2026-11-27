import getConfig from '../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

/*
 * Harness for an API that requires a passkey sign-in across every grant (specs/143 US2).
 * Uses non-default ACR names to prove configured `acrMap.phishing_resistant` is emitted on every
 * access token for the API while ID tokens and non-passkey APIs keep spec 142's reporting rule.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'profile', 'email', 'offline_access'],
	'deviceFlow.enabled': true,
	'ciba.enabled': true,
	'ciba.deliveryModes': ['poll'],
	'clientCredentials.enabled': true,
	'jwtBearer.enabled': true,
	'introspection.enabled': true,
	'claimsParameter.enabled': true,
	'federation.enabled': true,
	'personActivity.enabled': true,
	acrValues: {
		password: 'urn:example:acr:pwd',
		multi_factor: 'urn:example:acr:mfa',
		phishing_resistant: 'urn:example:acr:phr',
		federated: 'urn:example:acr:federated'
	}
};

export const addons: Partial<AddonImplementations> = {
	rotateRefreshToken() {
		return true;
	},
	issueRefreshToken(_ctx, client) {
		return client.grantTypes.includes('refresh_token');
	}
};

export const clients = [
	{
		clientId: 'acme-app',
		client_name: 'Acme App',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://acme-app.apps.test/cb'],
		scope: 'openid profile email offline_access',
		'consent.require': false
	},
	{
		clientId: 'acme-machine',
		clientSecret: 'machine-secret',
		client_name: 'Acme Machine',
		grantTypes: [
			'client_credentials',
			'urn:ietf:params:oauth:grant-type:jwt-bearer'
		],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'acme-tv',
		client_name: 'Acme TV',
		grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		applicationType: 'native'
	},
	{
		clientId: 'acme-ciba',
		clientSecret: 'ciba-secret',
		client_name: 'Acme CIBA',
		grantTypes: ['urn:openid:params:grant-type:ciba'],
		responseTypes: [],
		redirectUris: [],
		backchannel_token_delivery_mode: 'poll'
	},
	{
		clientId: 'acme-exchanger',
		clientSecret: 'exchanger-secret',
		client_name: 'Vault Exchanger',
		grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
		responseTypes: [],
		redirectUris: []
	}
];

export default { config };
