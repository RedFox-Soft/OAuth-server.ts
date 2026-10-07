import { Elysia, t } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { recordBootstrapAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import { ensurePersonalGroup } from '../groups/personal.js';
import epochTime from '../../helpers/epoch_time.js';
import { grantSuperAdmin, hasActiveSuperAdmin } from '../super_admins.js';

/* The claim that decides which of several concurrent setup requests runs. Held seconds, not minutes. */
const SETUP_CLAIM_ISSUER = 'admin-setup';
const SETUP_CLAIM_ID = 'bootstrap';
const SETUP_CLAIM_SECONDS = 60;

/* Setup stays closed while Super administrators has an active member. */
export async function hasSuperAdmin(): Promise<boolean> {
	return hasActiveSuperAdmin();
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
		const closed = () => {
			set.status = 409;
			return { error: 'already_initialized', message: 'setup is closed' };
		};
		if (await hasSuperAdmin()) return closed();

		/*
		 * The check above and the creation below sit either side of a password hash, so two requests
		 * arriving together both found setup open, and whoever raced the operator at first boot became a
		 * silent second super administrator. One insert-if-absent claim decides which request runs; the
		 * other is refused as closed. The claim is released when this request is done, succeeded or not —
		 * a success closes setup through `hasSuperAdmin`, and a failure must leave it open to retry — and
		 * it expires on its own should the process die holding it.
		 *
		 * Imported here rather than at the top: the model graph must not be entered cold from a module
		 * the admin routes load (wiki/concepts/model-graph-import-order.md).
		 */
		const { ReplayDetection } =
			await import('../../models/replay_detection.js');
		if (
			!(await ReplayDetection.unique(
				SETUP_CLAIM_ISSUER,
				SETUP_CLAIM_ID,
				epochTime() + SETUP_CLAIM_SECONDS
			))
		) {
			return closed();
		}
		try {
			if (await hasSuperAdmin()) return closed();
			return await bootstrap(body, set);
		} finally {
			await ReplayDetection.release(SETUP_CLAIM_ISSUER, SETUP_CLAIM_ID);
		}
	},
	{
		body: t.Object({
			email: t.String({ format: 'email' }),
			password: t.String({ minLength: 12 })
		})
	}
);

async function bootstrap(
	body: { email: string; password: string },
	set: { status?: number | string }
) {
	const hash = await Bun.password.hash(body.password);
	/*
	 * Audit-first, like every other state-changing admin action — which means the id has to be
	 * allocated here rather than by the store, since the entry must name the account that is
	 * about to exist. There is no session to attribute: the bootstrap actor stands in.
	 */
	const userId = nanoid();
	await recordBootstrapAudit('setup.bootstrap', userId);
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		body.email,
		hash,
		false,
		userId
	);
	// The bootstrap administrator gets a personal group like any other, so first-run setup and the
	// admin-create route leave an account in the same shape — and is the first super administrator.
	await ensurePersonalGroup(user._id, user.email);
	await grantSuperAdmin(user._id);
	set.status = 201;
	return { ok: true };
}
