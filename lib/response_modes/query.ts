import formatUri from '../helpers/redirect_uri.ts';
import type { ResponseModeHandler } from './index.ts';

const query: ResponseModeHandler = (_oidc, redirectUri, payload) => {
	return Response.redirect(formatUri(redirectUri, payload), 303);
};

export default query;
