import { shouldChange, mustChange } from './_warn.ts';
import * as errors from '../helpers/errors.ts';

export async function processLoginHintToken(ctx, loginHintToken) {
	// @param ctx - koa request context
	// @param loginHintToken - string value of the login_hint_token parameter
	mustChange(
		'features.ciba.processLoginHintToken',
		'process the login_hint_token parameter and return the accountId value to use for processsing the request'
	);
	throw new Error('features.ciba.processLoginHintToken not implemented');
}

export async function processLoginHint(ctx, loginHint) {
	// @param ctx - koa request context
	// @param loginHint - string value of the login_hint parameter
	mustChange(
		'features.ciba.processLoginHint',
		'process the login_hint parameter and return the accountId value to use for processsing the request'
	);
	throw new Error('features.ciba.processLoginHint not implemented');
}

export async function verifyUserCode(ctx, account, userCode) {
	// @param ctx - koa request context
	// @param account -
	// @param userCode - string value of the user_code parameter, when not provided it is undefined
	mustChange(
		'features.ciba.verifyUserCode',
		'verify the user_code parameter is present when required and verify its value'
	);
	throw new Error('features.ciba.verifyUserCode not implemented');
}

export async function validateBindingMessage(ctx, bindingMessage) {
	// @param ctx - koa request context
	// @param bindingMessage - string value of the binding_message parameter, when not provided it is undefined
	shouldChange(
		'features.ciba.validateBindingMessage',
		'verify the binding_message parameter is present when required and verify its value'
	);
	if (bindingMessage && !/^[a-zA-Z0-9-._+/!?#]{1,20}$/.exec(bindingMessage)) {
		throw new errors.InvalidBindingMessage(
			'the binding_message value, when provided, needs to be 1 - 20 characters in length and use only a basic set of characters (matching the regex: ^[a-zA-Z0-9-._+/!?#]{1,20}$ )'
		);
	}
}

export async function validateRequestContext(ctx, requestContext) {
	// @param ctx - koa request context
	// @param requestContext - string value of the request_context parameter, when not provided it is undefined
	mustChange(
		'features.ciba.validateRequestContext',
		'verify the request_context parameter is present when required and verify its value'
	);
	throw new Error('features.ciba.validateRequestContext not implemented');
}

export async function triggerAuthenticationDevice(ctx, request, account, client) {
	// @param ctx - koa request context
	// @param request - the BackchannelAuthenticationRequest instance
	// @param account - the account object retrieved by findAccount
	// @param client - the Client instance
	mustChange(
		'features.ciba.triggerAuthenticationDevice',
		"to trigger the authentication and authorization process on end-user's Authentication Device"
	);
	throw new Error('features.ciba.triggerAuthenticationDevice not implemented');
}
