import { Elysia, t } from 'elysia';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { KeyActionRefused } from '../key_lifecycle.js';
import { RetireKeyBody } from './schema.js';
import { generateKey, listKeys, promoteKey, retireKey } from './service.js';

// Super-admin management of the root issuer's keys. Every action flows through this management API
// with the same auth/validation as other admin operations (no privileged bypass), and every mutation is
// recorded in the append-only admin audit trail before it takes effect (see ../key_lifecycle.ts).
export const jwksRoutes = new Elysia({ name: 'admin-jwks' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return error instanceof KeyActionRefused
				? { ...adminErrorBody(error), ...error.detail }
				: adminErrorBody(error);
		}
	})
	.get('/admin/api/jwks', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertSuperAdmin(ctx);
		return listKeys(ctx);
	})
	.post(
		'/admin/api/jwks',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertSuperAdmin(ctx);
			return generateKey(ctx, (body as { alg?: unknown }).alg);
		},
		// Loose body + manual validation in the service, so failures return the admin_error
		// shape (matching the settings module) rather than a generic TypeBox error.
		{ body: t.Record(t.String(), t.Unknown()) }
	)
	.post('/admin/api/jwks/:kid/promote', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertSuperAdmin(ctx);
		return promoteKey(ctx, params.kid);
	})
	.delete(
		'/admin/api/jwks/:kid',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertSuperAdmin(ctx);
			return retireKey(ctx, params.kid, body?.confirm);
		},
		{ body: t.Optional(RetireKeyBody) }
	);
