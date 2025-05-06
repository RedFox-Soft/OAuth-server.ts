import formatUri from '../helpers/redirect_uri.ts';

export default (ctx, redirectUri, payload) => {
	return formatUri(redirectUri, payload);
};
