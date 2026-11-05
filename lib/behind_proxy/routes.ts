import { Elysia } from 'elysia';

import { BEHIND_PROXY_CHECK_ROUTE } from '../consts/behind_proxy.js';
import { answerCheck } from './check.js';

/*
 * The check endpoint (specs/122 R1), mounted bare and beneath `/:bucket` as every bucket-scoped surface is; the
 * address names the project and the path names the app.
 *
 * No `params` schema: the bare mount has only `appId` and the prefixed one has `bucket` too, and a schema naming
 * one would refuse the other (the app runs `strictPath`). No body is read, so none is parsed: a proxy may send the
 * check with the original method and whatever content type it carried.
 */
export const behindProxyRoutes = new Elysia({ name: 'behind-proxy' }).all(
	BEHIND_PROXY_CHECK_ROUTE,
	({ params, request, route }) => answerCheck({ params, request, route }),
	{ parse: 'none' }
);
