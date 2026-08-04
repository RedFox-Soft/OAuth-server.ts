import { Elysia, t } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { recordBootstrapAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';

export async function hasSuperAdmin(): Promise<boolean> {
	const users = await getUserStore(ADMIN_BUCKET_ID).list();
	return users.some((u) => u.roles.includes('super_admin'));
}

/*
 * The bootstrap API only. There is deliberately no GET page here: `GET /admin` already server-renders
 * the first-run <Setup /> screen when hasSuperAdmin() is false, with props, a cache-busted bundle and
 * a favicon. A second, hand-written page competing with it is how the old one drifted into pointing
 * at an unserved bundle address and rendering an empty document.
 */
export const adminSetup = new Elysia({ name: 'admin-setup' }).post(
	'/admin/api/setup',
	async ({ body, set }) => {
		if (await hasSuperAdmin()) {
			set.status = 409;
			return { error: 'already_initialized', message: 'setup is closed' };
		}
		const hash = await Bun.password.hash(body.password);
		/*
		 * Audit-first, like every other state-changing admin action — which means the id has to be
		 * allocated here rather than by the store, since the entry must name the account that is
		 * about to exist. There is no session to attribute: the bootstrap actor stands in.
		 */
		const userId = nanoid();
		await recordBootstrapAudit('setup.bootstrap', userId);
		await getUserStore(ADMIN_BUCKET_ID).create(
			body.email,
			hash,
			['super_admin'],
			false,
			userId
		);
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
