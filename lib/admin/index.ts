import { Elysia } from 'elysia';
import { captureFault } from '../error_store/capture.js';
import {
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from './auth/rbac.js';
import { safeNext } from './auth/next.js';
import { hasSuperAdmin } from './auth/setup.js';
import { adminApiRoutes } from './routes.js';
import { resolveAddress } from './ui/frame/routes.js';
import { renderAdminShell } from './ui/serverRender.js';
import { meView } from './me_view.js';

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
	.get('/admin', consolePage)
	.get('/admin/*', consolePage);

/*
 * Every console address is served the console, rendered at that address, so a link, a bookmark and a
 * reload open the page they name (specs/079). The route table in ui/frame/routes.ts is the one list of
 * addresses: this handler and the console's own router both read it, so the server cannot answer 200
 * for a page the console then has nothing to draw for.
 */
async function consolePage({
	admin,
	request,
	redirect,
	set
}: {
	admin: AdminContext | null;
	request: Request;
	redirect: (url: string, status: 302) => Response;
	set: { status?: number | string };
}) {
	const url = new URL(request.url);
	const path = `${url.pathname}${url.search}`;
	// The API never falls through to a page: a mistyped API path is a JSON 404 a client can read.
	if (url.pathname.startsWith('/admin/api/')) {
		set.status = 404;
		return { error: 'not_found', message: 'no such admin API route' };
	}
	if (!(await hasSuperAdmin())) {
		if (url.pathname !== '/admin') return redirect('/admin', 302);
		return renderAdminShell({ needsSetup: true, me: null, path: '/admin' });
	}
	const resolved = resolveAddress(url.pathname);
	// The one public page: the invitee following the link from their mail has no session yet.
	if (resolved.kind === 'page' && resolved.route.public) {
		return renderAdminShell({ needsSetup: false, me: null, path });
	}
	if (!admin) {
		return redirect(
			`/admin/login?next=${encodeURIComponent(safeNext(path))}`,
			302
		);
	}
	if (resolved.kind === 'redirect')
		return redirect(resolved.to + url.search, 302);
	return renderAdminShell(
		{ needsSetup: false, me: meView(admin), path },
		resolved.kind === 'none' ? 404 : 200
	);
}
