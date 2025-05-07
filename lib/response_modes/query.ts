import formatUri from '../helpers/redirect_uri.ts';

export default (ctx, redirectUri, payload) => {
	return Response.redirect(formatUri(redirectUri, payload), 303);
};
