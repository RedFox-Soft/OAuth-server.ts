import {
	validateRequestContext,
	validateBindingMessage
} from '../../addon/index.js';

export default async function checkCibaContext(oidc) {
	// validateRequestContext/validateBindingMessage are user-overridable callbacks expecting
	// a `ctx`-shaped arg
	await Promise.all([
		validateRequestContext({ oidc }, oidc.params.request_context),
		validateBindingMessage({ oidc }, oidc.params.binding_message)
	]);
}
