import { provider } from './provider.ts';
import * as errors from './helpers/errors.ts';
import * as interactionPolicy from './helpers/interaction_policy/index.ts';

export default provider;
export { errors, interactionPolicy, provider };
export { ExternalSigningKey } from './helpers/keystore.ts';

import { Elysia } from 'elysia';
import { errorHandler } from './shared/authorization_error_handler.js';
import { nocache } from './shared/no_cache.js';
import { authorizationAction } from './actions/authorization/authorization.js';
import { tokenAction } from './actions/token.js';

export const elysia = new Elysia({ strictPath: true })
	.onError(errorHandler)
	.use(nocache)
	.use(authorizationAction)
	.use(tokenAction);
