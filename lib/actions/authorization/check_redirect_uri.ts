import { InvalidRedirectUri, InvalidRequest } from '../../helpers/errors.ts';
import { ApplicationConfig } from '../../configs/application.js';
import { validateRedirectUri } from 'lib/helpers/validateRedirectUri.js';

function allowUnregisteredUri(oidc) {
	return (
		(oidc.route === '/par' || 'PushedAuthorizationRequest' in oidc.entities) &&
		ApplicationConfig['par.allowUnregisteredRedirectUris'] &&
		oidc.client.sectorIdentifierUri === undefined &&
		oidc.client.clientAuthMethod !== 'none'
	);
}

/*
 * Checks that provided redirect_uri is allowed
 */
export default function checkRedirectUri(oidc) {
	if (!oidc.client.redirectUriAllowed(oidc.params.redirect_uri)) {
		if (!allowUnregisteredUri(oidc)) {
			throw new InvalidRedirectUri();
		}

		validateRedirectUri(
			[oidc.params.redirect_uri],
			oidc.client.applicationType,
			{ label: 'redirect_uri', ErrorClass: InvalidRequest }
		);
	}

	oidc.redirectUriCheckPerformed = true;
}
