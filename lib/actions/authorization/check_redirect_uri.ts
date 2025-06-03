import { InvalidRedirectUri, InvalidRequest } from '../../helpers/errors.ts';
import { ApplicationConfig } from '../../configs/application.js';

function allowUnregisteredUri(ctx) {
	return (
		(ctx.oidc.route === '/par' ||
			'PushedAuthorizationRequest' in ctx.oidc.entities) &&
		ApplicationConfig['par.allowUnregisteredRedirectUris'] &&
		ctx.oidc.client.sectorIdentifierUri === undefined &&
		ctx.oidc.client.clientAuthMethod !== 'none'
	);
}

function validateUnregisteredUri(ctx) {
	const { redirectUris: validator } = ctx.oidc.provider.Client.Schema.prototype;

	validator.call(
		{
			...ctx.oidc.client.metadata(),
			invalidate(detail) {
				throw new InvalidRequest(
					detail.replace('redirect_uris', 'redirect_uri')
				);
			}
		},
		[ctx.oidc.params.redirect_uri]
	);

	return true;
}

/*
 * Checks that provided redirect_uri is allowed
 */
export default function checkRedirectUri(ctx) {
	if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri)) {
		if (!allowUnregisteredUri(ctx)) {
			throw new InvalidRedirectUri();
		}

		validateUnregisteredUri(ctx);
	}

	ctx.oidc.redirectUriCheckPerformed = true;
}
