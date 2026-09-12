import {
	InvalidRedirectUri,
	InvalidRequest,
	InvalidRequestObject
} from '../../helpers/errors.ts';
import { ApplicationConfig } from '../../configs/application.js';
import { validateRedirectUri } from 'lib/helpers/validateRedirectUri.js';
import { routeNames } from 'lib/consts/param_list.js';

const UNREGISTERED =
	"redirect_uri did not match any of the client's registered redirectUris";

/*
 * WHY the code depends on which endpoint refused. `invalid_redirect_uri` is RFC 7591 §3.2.2, a
 * dynamic client registration code, and it has no definition in a pushed authorization response —
 * RFC 9126 §2.3 prints that response and gives `invalid_request`, adding that an extension's own
 * code may be used "when such an extension is involved", which is where `invalid_request_object`
 * comes from on the JAR path.
 *
 * The authorization endpoint keeps `invalid_redirect_uri` because RFC 6749 §4.1.2.1 forbids
 * redirecting this error at all: the refusal there is a rendered page, not a protocol response, and
 * no specification defines a code for it.
 */
function refusal(oidc) {
	if (oidc.route !== routeNames.pushed_authorization_request) {
		return new InvalidRedirectUri();
	}

	return oidc.trusted?.includes('redirect_uri')
		? new InvalidRequestObject(UNREGISTERED)
		: new InvalidRequest(UNREGISTERED);
}

function allowUnregisteredUri(oidc) {
	return (
		(oidc.route === routeNames.pushed_authorization_request ||
			'PushedAuthorizationRequest' in oidc.entities) &&
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
			throw refusal(oidc);
		}

		validateRedirectUri(
			[oidc.params.redirect_uri],
			oidc.client.applicationType,
			{ label: 'redirect_uri', ErrorClass: InvalidRequest }
		);
	}

	oidc.redirectUriCheckPerformed = true;
}
