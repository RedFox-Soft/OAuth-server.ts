import formatUri from '../helpers/redirect_uri.ts';

export default (_oidc, redirectUri, payload) => {
	return Response.redirect(formatUri(redirectUri, payload), 303);
};
