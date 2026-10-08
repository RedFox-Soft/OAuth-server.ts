import { Elysia } from 'elysia';

import {
	resolveAdmin,
	assertAuth,
	AdminError,
	adminErrorBody
} from './auth/rbac.js';

/*
 * Who the caller is, as the admin plane resolved them: id, email, whether a super administrator, bucket
 * and the groups they belong to.
 *
 * Its own plugin rather than an inline route on `adminApp`, because two surfaces mount it. It was
 * inline until the MCP control plane needed it: the `whoami` tool re-dispatches into this route, and
 * `lib/mcp/dispatch.ts` composes route plugins rather than `adminApp` — importing `adminApp` pulls
 * `renderAdminShell` and with it React and antd's CSS-in-JS, measured at ~86s to load against ~350ms
 * for the plugins.
 */
export const meRoutes = new Elysia({ name: 'admin-me' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/me', ({ admin }) => {
		const ctx = assertAuth(admin);
		return ctx;
	});
