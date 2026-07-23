import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * If no redirect_uri is provided and client only pre-registered one unique value it is assumed
 * to be the requested redirect_uri and used as if it was explicitly provided; gated behind the
 * named OAuth 2.1 deviation flag (off by default).
 */
export default function oneRedirectUriClients(oidc) {
	if (
		!ApplicationConfig['authorization.allowOmittingSingleRegisteredRedirectUri']
	) {
		return;
	}

	const { params, client } = oidc;

	if (params.redirect_uri === undefined && client.redirectUris.length === 1) {
		oidc.redirectUriCheckPerformed = true;
		[params.redirect_uri] = client.redirectUris;
	}
}
