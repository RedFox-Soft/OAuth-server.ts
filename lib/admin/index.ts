import { Elysia } from 'elysia';
import { AdminError, adminErrorBody, resolveAdmin } from './auth/rbac.js';
import { hasSuperAdmin } from './auth/setup.js';
import { adminApiRoutes } from './routes.js';
import { renderAdminShell } from './ui/serverRender.js';

/*
 * The console: the admin API plus the HTML shell that drives it.
 *
 * The API itself lives in ./routes.ts, because the MCP control plane mounts the same route set to
 * re-dispatch agent tool calls into it — one definition, so a route cannot exist for one surface and
 * not the other, and the MCP parity guard has something exact to compare against.
 */
export const adminApp = new Elysia({ name: 'admin' })
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.use(adminApiRoutes)
	.use(resolveAdmin)
	.get('/admin', async ({ admin, redirect }) => {
		if (!(await hasSuperAdmin())) {
			return renderAdminShell({ needsSetup: true, me: null });
		}
		if (!admin) return redirect('/admin/login', 302);
		return renderAdminShell({ needsSetup: false, me: admin });
	});
