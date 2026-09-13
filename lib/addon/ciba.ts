import { shouldChange, mustChange } from './_warn.ts';
import * as errors from '../helpers/errors.ts';

export async function processLoginHintToken(_ctx, _loginHintToken) {
	// @param ctx - koa request context
	// @param loginHintToken - string value of the login_hint_token parameter
	mustChange(
		'features.ciba.processLoginHintToken',
		'process the login_hint_token parameter and return the accountId value to use for processsing the request'
	);
	throw new Error('features.ciba.processLoginHintToken not implemented');
}

export async function processLoginHint(_ctx, _loginHint) {
	// @param ctx - koa request context
	// @param loginHint - string value of the login_hint parameter
	mustChange(
		'features.ciba.processLoginHint',
		'process the login_hint parameter and return the accountId value to use for processsing the request'
	);
	throw new Error('features.ciba.processLoginHint not implemented');
}

export async function verifyUserCode(_ctx, _account, _userCode) {
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

export async function validateRequestContext(_ctx, _requestContext) {
	// @param ctx - koa request context
	// @param requestContext - string value of the request_context parameter, when not provided it is undefined
	mustChange(
		'features.ciba.validateRequestContext',
		'verify the request_context parameter is present when required and verify its value'
	);
	throw new Error('features.ciba.validateRequestContext not implemented');
}

export async function triggerAuthenticationDevice(
	_ctx,
	_request,
	_account,
	_client
) {
	// @param ctx - koa request context
	// @param request - the BackchannelAuthenticationRequest instance
	// @param account - the account object retrieved by findAccount
	// @param client - the Client instance
	/*
	 * Two things about the authentication context (`acr`) belong to whoever implements this, because
	 * the sign-in happens on the end user's own device and this server never sees it.
	 *
	 * Authenticate *in line with what was asked*: `request.payload.params.acr_values` carries the
	 * client's preferences and `request.payload.claims.id_token.acr` carries a requirement, if it
	 * made one. CIBA §8 expects the provider to choose the channel accordingly, and only this
	 * function can.
	 *
	 * Then report what was actually satisfied, by passing `acr` to `backchannelResult`. CIBA §7.1
	 * makes it highly recommended that a token carry the claim when a context was requested, and
	 * this server will not invent one — a value it made up would be a false statement about an
	 * authentication it did not perform. Where the client made the claim *essential*, a reported
	 * context that does not match (or none at all) is recorded as a failed transaction instead of
	 * issuing a token, per OIDC Core §5.5.1.1.
	 */
	mustChange(
		'features.ciba.triggerAuthenticationDevice',
		"to trigger the authentication and authorization process on end-user's Authentication Device"
	);
	throw new Error('features.ciba.triggerAuthenticationDevice not implemented');
}
