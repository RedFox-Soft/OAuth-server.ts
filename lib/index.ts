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
import { userinfo } from './actions/userinfo.js';
import { backchannelAuth, deviceAuth } from './actions/authorization/device.js';

export const elysia = new Elysia({ strictPath: true, normalize: 'exactMirror' })
	.onError(errorHandler)
	.use(staticPlugin({ assets: 'dist' }))
	.use(staticPlugin())
	.use(nocache)
	.use(discovery)
	.use(authGet)
	.use(authPost)
	.use(deviceAuth)
	.use(backchannelAuth)
	.use(par)
	.use(tokenAction)
	.use(userinfo)
	.use(ui)
	.listen(8080);
