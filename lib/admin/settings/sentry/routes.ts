import { Elysia } from 'elysia';

import { ApplicationConfig } from '../../../configs/application.js';
import {
	validateConfiguration,
	type ConfigurationInput
} from '../../../configs/configuration.js';
import { configStore } from '../../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../../auth/rbac.js';
import { recordAdminAudit } from '../../audit/record.js';
import { eventLabels } from '../../../sentry/labels.js';
import { SENTRY_TARGET_ID } from '../../../consts/admin_audit_routes.js';
import { SENTRY_DSN_MASK, UpdateSentryBody } from './schema.js';

/*
 * The Sentry card: the integration's settings, with the credential write-only.
 *
 * A card of its own rather than four more entries in the generic settings catalog, and the reason is
 * the credential. That catalog is the generic surface's *read* projection — `stateFor` builds the
 * response by iterating it — so a key described there is a key returned to whoever can read
 * settings. The credential must never be returned, so it is absent from the catalog (which also
 * makes the generic PUT refuse it, for free) and handled here instead.
 *
 * `sentry.enabled` is an ordinary catalog entry and is editable from either surface. It is repeated
 * here so the card can enable reporting and store a credential in one request — which it must, since
 * enabling without a credential is refused.
 */
const SENTRY_KEYS = ['sentry.enabled', 'sentry.dsn'] as const;

type StoredOverrides = Record<string, unknown>;

async function storedOverrides(): Promise<StoredOverrides> {
	return ((await configStore.get()) ?? {}) as StoredOverrides;
}

/* The value that would be in force after a restart: the stored override, else what is running. */
function inForce(stored: StoredOverrides, key: (typeof SENTRY_KEYS)[number]) {
	return Object.prototype.hasOwnProperty.call(stored, key)
		? stored[key]
		: (ApplicationConfig as Record<string, unknown>)[key];
}

/*
 * The client-facing view. `configured` is the only thing ever said about the credential — not a
 * prefix, not a length, not a masked remainder. Anything more would be a partial disclosure of a
 * value whose whole point is to be unreadable once written.
 */
function present(stored: StoredOverrides) {
	const dsn = String(inForce(stored, 'sentry.dsn') ?? '');
	const running = ApplicationConfig as Record<string, unknown>;
	const restartRequired = SENTRY_KEYS.some(
		(key) =>
			JSON.stringify(inForce(stored, key)) !== JSON.stringify(running[key])
	);

	/*
	 * The labels are reported, not stored: they come from the deployment, and the console shows them so
	 * an operator can confirm where events will be filed without having to read the environment.
	 */
	const labels = eventLabels();

	return {
		enabled: Boolean(inForce(stored, 'sentry.enabled')),
		configured: dsn.trim().length > 0,
		environment: labels.environment,
		release: labels.release ?? '',
		restartRequired
	};
}

export const sentrySettingsRoutes = new Elysia({
	name: 'admin-settings-sentry'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/settings/sentry', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		/*
		 * Super-admin for the read as well as the write. The destination is instance-wide — one project
		 * for the whole server, by requirement — so there is no scoped view of it that would mean
		 * anything to a project administrator.
		 */
		assertRole(ctx, 'super_admin');
		return present(await storedOverrides());
	})
	.put(
		'/admin/api/settings/sentry',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');

			const stored = await storedOverrides();

			/*
			 * Three meanings, and the empty one differs from the SMTP card on purpose.
			 *
			 * The mask keeps the stored credential; an empty value *clears* it; anything else replaces
			 * it. SMTP treats empty as "keep" because its password field is always on screen, so an
			 * untouched form submits blank. Here the input is shown only when nothing is stored, so a
			 * blank submission can only mean "there should be no credential" — which is what the
			 * console's remove action sends, together with `enabled: false`.
			 *
			 * Clearing while reporting was still on would leave a configuration the server refuses, so
			 * the two travel in one request and the validator below is what enforces that.
			 */
			const submitted = body.dsn.trim();
			const dsn =
				submitted === SENTRY_DSN_MASK
					? String(inForce(stored, 'sentry.dsn') ?? '')
					: submitted;

			const changes: StoredOverrides = {
				'sentry.enabled': body.enabled,
				'sentry.dsn': dsn
			};

			/*
			 * Judged on the whole merged result rather than on these five keys alone, and through the
			 * boot validator rather than a restatement of its rules. Both matter: the prerequisite that
			 * reporting requires the error store is a cross-key invariant that cannot be seen from here,
			 * and a second copy of the rules would drift from the one that actually decides at startup.
			 */
			const merged = { ...stored, ...changes };
			try {
				validateConfiguration({
					...ApplicationConfig,
					...merged
				} as ConfigurationInput);
			} catch (err) {
				// Every failure it raises describes an unrunnable configuration, which is a refused
				// submission here rather than a server fault.
				throw new AdminError(
					422,
					err instanceof Error ? err.message : String(err)
				);
			}

			/*
			 * Only what actually moved is recorded. The card is a full replace, so all five fields
			 * arrive on every save, and naming all five every time would say nothing about what an
			 * operator did — on the one surface whose whole purpose is to be trusted about that.
			 */
			const changed = SENTRY_KEYS.filter(
				(key) =>
					JSON.stringify(changes[key]) !== JSON.stringify(inForce(stored, key))
			);
			if (changed.length === 0) {
				return present(stored);
			}

			/*
			 * Audit-first: a persisted change must never outlive a failed audit write. Field names only
			 * — that the credential was among them is worth recording, its value never is.
			 */
			await recordAdminAudit(ctx, 'sentry.settings.update', SENTRY_TARGET_ID, {
				attributes: [...changed]
			});
			await configStore.set(merged);
			return present(await storedOverrides());
		},
		{ body: UpdateSentryBody }
	);
