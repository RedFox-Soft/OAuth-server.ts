import { Elysia } from 'elysia';

import { AdminError, adminErrorBody, resolveAdmin } from './auth/rbac.js';
import { adminSetup } from './auth/setup.js';
import { adminLogin } from './auth/login.js';
import { meRoutes } from './me.js';
import { projectRoutes } from './projects/routes.js';
import { clientRoutes } from './clients/routes.js';
import { adminUserRoutes } from './users/routes.js';
import { bucketRoutes } from './buckets/routes.js';
import { federationAdminRoutes } from './federation/routes.js';
import { endUserRoutes } from './users-end/routes.js';
import { settingsRoutes } from './settings/routes.js';
import { smtpSettingsRoutes } from './settings/smtp/routes.js';
import { jwksRoutes } from './jwks/routes.js';
import { auditRoutes } from './audit/routes.js';
import { errorRoutes } from './errors/routes.js';

/*
 * Every route of the administrative control plane except the console's own HTML shell.
 *
 * Split out of `index.ts` so there is exactly one definition of "the admin API", mounted by two
 * consumers: `adminApp` adds the shell on top, and `lib/mcp/dispatch.ts` re-dispatches agent tool
 * calls into it. That single source is what makes the MCP surface's parity guard meaningful — the
 * drift check compares the tool catalogue against *this* route set, so a route added here is either
 * published to agents, named as a deliberate exclusion, or a test failure.
 *
 * The MCP layer must not mount `adminApp` instead: `renderAdminShell` pulls React and antd's CSS-in-JS,
 * measured at ~86s to import against ~350ms for these plugins.
 */
export const adminApiRoutes = new Elysia({ name: 'admin-api' })
	.onError(({ code, error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
		/*
		 * Keeps admin responses in the admin `{ error, message }` shape instead of letting
		 * request-validation errors fall through to the global OAuth (RFC 6749) error handler used by the
		 * protocol routes.
		 *
		 * The route groups each own the AdminError arm above, but none owns this one — so a composition
		 * of them without this instance answers a validation failure in Elysia's own shape. Measured by
		 * `test/mcp/dispatch_contract.spec.ts`, which is why the arm lives here rather than only on
		 * `adminApp`: both consumers need it.
		 */
		if (code === 'VALIDATION') {
			set.status = 422;
			return { error: 'invalid_request', message: error.message };
		}
	})
	.use(adminSetup)
	.use(adminLogin)
	.use(resolveAdmin)
	.use(meRoutes)
	.use(projectRoutes)
	.use(clientRoutes)
	.use(adminUserRoutes)
	.use(bucketRoutes)
	.use(federationAdminRoutes)
	.use(endUserRoutes)
	.use(settingsRoutes)
	.use(smtpSettingsRoutes)
	.use(jwksRoutes)
	.use(auditRoutes)
	.use(errorRoutes);
