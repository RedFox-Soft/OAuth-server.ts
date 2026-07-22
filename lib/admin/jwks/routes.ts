import { Elysia, t } from 'elysia';
import {
	assertAuth,
	assertRole,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { getJwksState, generateKey, deleteKey } from './service.js';

// Super-admin JWKS (signing-key) management. Every action flows through this management API
// with the same auth/validation as other admin operations (no privileged bypass), and every
// mutation is recorded in the append-only admin audit trail (see service.ts).
export const jwksRoutes = new Elysia({ name: 'admin-jwks' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.get('/admin/api/jwks', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return getJwksState();
	})
	.post(
		'/admin/api/jwks',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			return generateKey(ctx, (body as { alg?: unknown }).alg);
		},
		// Loose body + manual validation in the service, so failures return the admin_error
		// shape (matching the settings module) rather than a generic TypeBox error.
		{ body: t.Record(t.String(), t.Unknown()) }
	)
	.delete('/admin/api/jwks/:kid', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return deleteKey(ctx, params.kid);
	});
