import getConfig from '../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

/*
 * Every surface that accepts the `claims` request parameter, switched on at once, so one spec can
 * exercise all of them. Separate from claims.config.ts because that one deliberately runs the
 * authorization endpoint alone.
 */
export const ApplicationConfig = {
	'claimsParameter.enabled': true,
	'par.enabled': true,
	'deviceFlow.enabled': true,
	'ciba.enabled': true,
	'ciba.deliveryModes': ['poll'],
	'requestObjects.enabled': true
};

/*
 * CIBA's request-context hook has no default implementation — it throws until a deployment supplies
 * one — so without this the backchannel endpoint answers 500 and the case below would pass on two
 * matched server errors rather than on two matched successes.
 */
export const addons: Partial<AddonImplementations> = {
	validateRequestContext() {},
	verifyUserCode() {},
	triggerAuthenticationDevice() {},
	processLoginHint(_ctx, loginHint) {
		return loginHint;
	}
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: [
			'authorization_code',
			'urn:ietf:params:oauth:grant-type:device_code',
			'urn:openid:params:grant-type:ciba'
		],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb'],
		backchannel_token_delivery_mode: 'poll'
	}
];

export default {
	config
};
