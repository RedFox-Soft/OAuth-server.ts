/* eslint-disable prefer-rest-params */

import { strict as assert } from 'node:assert';
import * as events from 'node:events';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

import getConfig from '../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

export const emitter = new events.EventEmitter();

export const ApplicationConfig = {
	'encryption.enabled': true,
	'ciba.enabled': true,
	'ciba.deliveryModes': ['poll', 'ping']
};

export const addons: Partial<AddonImplementations> = {
	processLoginHint(oidc, loginHint) {
		assert(oidc instanceof OIDCContext);
		assert(typeof loginHint === 'string');
		emitter.emit('processLoginHint', ...arguments);
		return loginHint;
	},
	processLoginHintToken(oidc, loginHintToken) {
		assert(oidc instanceof OIDCContext);
		assert(typeof loginHintToken === 'string');
		emitter.emit('processLoginHintToken', ...arguments);
		if (loginHintToken === 'notfound') {
			return undefined;
		}
		return loginHintToken;
	},
	validateBindingMessage(oidc, bindingMessage) {
		assert(oidc instanceof OIDCContext);
		assert(bindingMessage === undefined || typeof bindingMessage === 'string');
		emitter.emit('validateBindingMessage', ...arguments);
	},
	validateRequestContext(oidc, requestContext) {
		assert(oidc instanceof OIDCContext);
		assert(requestContext === undefined || typeof requestContext === 'string');
		emitter.emit('validateRequestContext', ...arguments);
	},
	verifyUserCode(oidc, account, userCode) {
		assert(oidc instanceof OIDCContext);
		assert(account?.accountId && typeof account.claims === 'function');
		assert(userCode === undefined || typeof userCode === 'string');
		emitter.emit('verifyUserCode', ...arguments);
	},
	triggerAuthenticationDevice() {
		emitter.emit('triggerAuthenticationDevice', ...arguments);
	}
};

export const clients = [
	{
		clientId: 'client',
		grantTypes: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		backchannel_token_delivery_mode: 'poll'
	},
	{
		clientId: 'client-ping',
		grantTypes: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		backchannel_client_notification_endpoint: 'https://rp.example.com/ping',
		backchannel_token_delivery_mode: 'ping'
	},
	{
		clientId: 'client-signed',
		grantTypes: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'none',
		backchannel_token_delivery_mode: 'poll',
		'requestObject.backChannelSigningAlg': 'ES256',
		jwks_uri: 'https://rp.example.com/jwks'
	},
	{
		clientId: 'client-not-allowed',
		token_endpoint_auth_method: 'none',
		grantTypes: [],
		redirectUris: [],
		responseTypes: []
	}
];

export default {
	config
};
