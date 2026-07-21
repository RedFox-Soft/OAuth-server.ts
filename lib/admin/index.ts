import { Elysia } from 'elysia';
import {
	resolveAdmin,
	assertAuth,
	AdminError,
	type AdminContext
} from './auth/rbac.js';
import { adminSetup, hasSuperAdmin } from './auth/setup.js';
import { adminLogin } from './auth/login.js';
import { projectRoutes } from './projects/routes.js';
import { clientRoutes } from './clients/routes.js';
import { adminUserRoutes } from './users/routes.js';
import { bucketRoutes } from './buckets/routes.js';
import { endUserRoutes } from './users-end/routes.js';
import { settingsRoutes } from './settings/routes.js';
import { renderAdminShell } from './ui/serverRender.js';

export const adminApp = new Elysia({ name: 'admin' })
	.onError(({ code, error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
		// Keep admin responses in the admin `{ error, message }` shape instead of
		// letting request-validation errors fall through to the global OAuth
		// (RFC 6749) error handler used by the protocol routes.
		if (code === 'VALIDATION') {
			set.status = 422;
			return { error: 'invalid_request', message: error.message };
		}
	})
	.use(adminSetup)
	.use(adminLogin)
	.use(resolveAdmin)
	.get('/admin', async ({ admin, redirect }) => {
		if (!(await hasSuperAdmin())) {
			return renderAdminShell({ needsSetup: true, me: null });
		}
		if (!admin) return redirect('/admin/login', 302);
		return renderAdminShell({ needsSetup: false, me: admin });
	})
	.get('/admin/api/me', ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		return ctx;
	})
	.use(projectRoutes)
	.use(clientRoutes)
	.use(adminUserRoutes)
	.use(bucketRoutes)
	.use(endUserRoutes)
	.use(settingsRoutes);
