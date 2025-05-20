import { provider } from './provider.ts';
import * as errors from './helpers/errors.ts';
import * as interactionPolicy from './helpers/interaction_policy/index.ts';

export default provider;
export { errors, interactionPolicy, provider };
export { ExternalSigningKey } from './helpers/keystore.ts';

import { Elysia } from 'elysia';
import { staticPlugin } from '@elysiajs/static';

import { errorHandler } from './shared/authorization_error_handler.js';
import { nocache } from './plugins/noCache.js';
import {
	authGet,
	authPost,
	par
} from './actions/authorization/authorization.js';
import { tokenAction } from './actions/token.js';
import { ui } from './interactions/index.js';
import { discovery } from './actions/discovery.js';

export const elysia = new Elysia({ strictPath: true })
	.onError(errorHandler)
	.use(staticPlugin({ assets: 'dist' }))
	.use(staticPlugin())
	.use(nocache)
	.use(discovery)
	.use(authGet)
	.use(authPost)
	.use(par)
	.use(tokenAction)
	.use(ui)
	.listen(8080);
