import { Elysia, t } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../consts.js';

export async function hasSuperAdmin(): Promise<boolean> {
	const users = await getUserStore(ADMIN_BUCKET_ID).list();
	return users.some((u) => u.roles.includes('super_admin'));
}

export const adminSetup = new Elysia({ name: 'admin-setup' })
	.get('/admin/setup', async ({ redirect }) => {
		if (await hasSuperAdmin()) {
			return redirect('/admin/login', 302);
		}
		return new Response(
			'<!doctype html><meta charset=utf-8><div id=root></div><script src="/admin.js"></script>',
			{ headers: { 'content-type': 'text/html; charset=utf-8' } }
		);
	})
	.post(
		'/admin/api/setup',
		async ({ body, set }) => {
			if (await hasSuperAdmin()) {
				set.status = 409;
				return { error: 'already_initialized', message: 'setup is closed' };
			}
			const hash = await Bun.password.hash(body.password);
			await getUserStore(ADMIN_BUCKET_ID).create(body.email, hash, [
				'super_admin'
			]);
			set.status = 201;
			return { ok: true };
		},
		{
			body: t.Object({
				email: t.String({ format: 'email' }),
				password: t.String({ minLength: 12 })
			})
		}
	);
