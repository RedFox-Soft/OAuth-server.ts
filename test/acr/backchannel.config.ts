import getConfig from '../default.config.js';

const config = getConfig();

/*
 * CIBA ships off, so nothing else in the suite reaches this path. The claims parameter is on for the
 * reason acr.config.ts gives: without it an essential context cannot be stated, and the obligation
 * this file exercises does not arise.
 *
 * The addon overrides are the minimum CIBA needs to accept a request at all — their defaults throw
 * "not implemented", because only a deployment knows how to reach an end user's device. These cases
 * then complete the request by calling `backchannelResult` directly, which is what that deployment's
 * integration does when the person answers.
 */
export const addons = {
	processLoginHint: (_ctx: unknown, loginHint: string) => loginHint,
	validateBindingMessage: () => {},
	validateRequestContext: () => {},
	verifyUserCode: () => {},
	triggerAuthenticationDevice: () => {}
};
export const ApplicationConfig = {
	'ciba.enabled': true,
	'ciba.deliveryModes': ['poll', 'ping'],
	'claimsParameter.enabled': true,
	acrValues: {
		password: 'urn:example:acr:pwd',
		multi_factor: 'urn:example:acr:mfa',
		federated: 'urn:example:acr:federated'
	}
};

export const clients = [
	{
		clientId: 'ciba-poll',
		token_endpoint_auth_method: 'none',
		grantTypes: ['urn:openid:params:grant-type:ciba'],
		responseTypes: [],
		redirectUris: [],
		backchannel_token_delivery_mode: 'poll'
	},
	{
		clientId: 'ciba-ping',
		token_endpoint_auth_method: 'none',
		grantTypes: ['urn:openid:params:grant-type:ciba'],
		responseTypes: [],
		redirectUris: [],
		backchannel_client_notification_endpoint: 'https://rp.example.com/ping',
		backchannel_token_delivery_mode: 'ping'
	}
];

export default {
	config
};
