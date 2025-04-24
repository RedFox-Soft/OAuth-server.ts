import { InvalidRequest } from '../../helpers/errors.ts';

const GATED_CLIENT = Object.entries({
	defaultAcrValues: 'default_acr_values',
	defaultMaxAge: 'default_max_age',
	requireAuthTime: 'require_auth_time'
});

const GATED = [
	'acr_values',
	'claims',
	'claims_locales',
	'id_token_hint',
	'max_age',
	'nonce'
];

/*
 * Validates that openid scope is requested when openid specific parameters are provided
 */
export default function checkOpenIdScope(ctx) {
	if (ctx.oidc.params.scope?.split(' ').includes('openid')) {
		return;
	}

	GATED_CLIENT.forEach(([prop, msg]) => {
		if (ctx.oidc.client[prop]) {
			throw new InvalidRequest(
				`openid scope must be requested for clients with ${msg}`
			);
		}
	});

	GATED.forEach((param) => {
		if (ctx.oidc.params[param] !== undefined) {
			throw new InvalidRequest(
				`openid scope must be requested when using the ${param} parameter`
			);
		}
	});

	if (ctx.oidc.route === 'backchannel_authentication') {
		throw new InvalidRequest('openid scope must be requested for this request');
	}
}
