import { InvalidRedirectUri, InvalidRequest } from '../../helpers/errors.ts';
import { ApplicationConfig } from '../../configs/application.js';
import { validateRedirectUri } from 'lib/helpers/validateRedirectUri.js';

function allowUnregisteredUri(ctx) {
	return (
		(ctx.oidc.route === '/par' ||
			'PushedAuthorizationRequest' in ctx.oidc.entities) &&
		ApplicationConfig['par.allowUnregisteredRedirectUris'] &&
		ctx.oidc.client.sectorIdentifierUri === undefined &&
		ctx.oidc.client.clientAuthMethod !== 'none'
	);
}

/*
 * Checks that provided redirect_uri is allowed
 */
export default function checkRedirectUri(ctx) {
	if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri)) {
		if (!allowUnregisteredUri(ctx)) {
			throw new InvalidRedirectUri();
		}

		validateRedirectUri(
			[ctx.oidc.params.redirect_uri],
			ctx.oidc.client.applicationType,
			{ label: 'redirect_uri', ErrorClass: InvalidRequest }
		);
	}

	ctx.oidc.redirectUriCheckPerformed = true;
}
