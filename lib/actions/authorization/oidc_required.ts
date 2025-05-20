import presence from '../../helpers/validate_presence.ts';

/*
 * Validates presence of redirect_uri and conditionally nonce if specific implicit or hybrid flow
 * are used.
 * Validates that openid scope is present is OpenID Connect specific parameters are provided.
 */
export default function oidcRequired(ctx) {
	const required = new Set(['redirect_uri']);

	// TODO: move this to a new helper function
	if (ctx.oidc.isFapi('1.0 Final')) {
		required.add(ctx.oidc.requestParamScopes.has('openid') ? 'nonce' : 'state');
	}

	presence(ctx, ...required);
}
