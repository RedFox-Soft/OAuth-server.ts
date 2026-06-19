import instance from '../../helpers/weak_cache.ts';

/*
 * If no redirect_uri is provided and client only pre-registered one unique value it is assumed
 * to be the requested redirect_uri and used as if it was explicitly provided;
 */
export default function oneRedirectUriClients(oidc) {
	if (
		!instance(oidc.provider).configuration
			.allowOmittingSingleRegisteredRedirectUri
	) {
		return;
	}

	const { params, client } = oidc;

	if (params.redirect_uri === undefined && client.redirectUris.length === 1) {
		oidc.redirectUriCheckPerformed = true;
		[params.redirect_uri] = client.redirectUris;
	}
}
