import instance from '../../helpers/weak_cache.ts';

export default async function checkCibaContext(oidc) {
	const { ciba } = instance(oidc.provider).features;

	// validateRequestContext/validateBindingMessage are user-overridable callbacks expecting
	// a `ctx`-shaped arg
	await Promise.all([
		ciba.validateRequestContext({ oidc }, oidc.params.request_context),
		ciba.validateBindingMessage({ oidc }, oidc.params.binding_message)
	]);
}
