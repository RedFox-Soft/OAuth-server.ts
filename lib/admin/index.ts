import { Elysia } from 'elysia';
import { captureFault } from '../error_store/capture.js';
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
	.onError(({ error, set, route, request }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			/*
			 * A 5xx AdminError is a genuine fault the plane happens to describe in its own words — the
			 * audit trail refusing a write is the one in practice — so it is recorded like any other, and
			 * the reference goes into the body an operator is already reading.
			 *
			 * This is the second of the two capture sites, and it exists because an AdminError carries the
			 * `adminPlane` marker the root handler stands aside for: without this, the only faults the
			 * store would miss are the ones the admin plane took the trouble to explain.
			 */
			const reference =
				error.status >= 500
					? captureFault({
							surface: 'admin',
							route,
							method: request.method,
							status: error.status,
							errorCode: 'admin_error',
							error,
							headers: request.headers
						})
					: undefined;
			const body = adminErrorBody(error);
			return reference ? { ...body, error_reference: reference } : body;
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
