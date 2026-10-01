import { describeQuery, send } from './describe.ts';
import type { ResponseModeHandler } from './index.ts';

const query: ResponseModeHandler = (oidc, redirectUri, payload) => {
	return send(oidc, describeQuery(redirectUri, payload));
};

export default query;
