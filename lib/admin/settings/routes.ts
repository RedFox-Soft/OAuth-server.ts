import { Elysia } from 'elysia';
import { ApplicationConfig } from '../../configs/application.js';
import {
	validateConfiguration,
	type ConfigurationInput
} from '../../configs/configuration.js';
import { configStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { recordAdminAudit } from '../audit/record.js';
import { SETTINGS_TARGET_ID } from '../../consts/admin_audit_routes.js';
import { SETTINGS_CATALOG, type SettingDescriptor } from './catalog.js';
import { UpdateSettingsBody } from './schema.js';

const CATALOG_BY_KEY = new Map<string, SettingDescriptor>(
	SETTINGS_CATALOG.map((d) => [d.key as string, d])
);

const running = (key: string): unknown =>
	(ApplicationConfig as Record<string, unknown>)[key];

const sameValue = (a: unknown, b: unknown): boolean =>
	JSON.stringify(a) === JSON.stringify(b);

// Validate one submitted value against its descriptor. Throws AdminError(422) on any
// type/option/invariant violation.
function validateValue(descriptor: SettingDescriptor, value: unknown): void {
	const { key, type, options } = descriptor;
	if (type === 'boolean') {
		if (typeof value !== 'boolean')
			throw new AdminError(422, `${key} must be a boolean`);
	} else if (type === 'string') {
		if (typeof value !== 'string')
			throw new AdminError(422, `${key} must be a string`);
	} else if (type === 'enum') {
		if (typeof value !== 'string' || !options?.includes(value))
			throw new AdminError(
				422,
				`${key} must be one of: ${options?.join(', ')}`
			);
	} else if (type === 'string-array') {
		if (!Array.isArray(value) || !value.every((v) => typeof v === 'string'))
			throw new AdminError(422, `${key} must be an array of strings`);
		if (options && !value.every((v) => options.includes(v as string)))
			throw new AdminError(
				422,
				`${key} values must be among: ${options.join(', ')}`
			);
		if (key === 'scopes' && !value.includes('openid'))
			throw new AdminError(422, 'scopes must include "openid"');
	} else if (type === 'json') {
		// Shape only. The semantic rules live in validateConfiguration, which validateEffectiveConfig
		// calls below — restating them here is the drift this module's own comment warns about.
		if (typeof value !== 'object' || value === null || Array.isArray(value))
			throw new AdminError(422, `${key} must be a JSON object`);
	} else {
		/*
		 * Deliberately loud. This used to be the `string-array` branch, so every setting type added
		 * after it silently inherited array-of-strings validation — a submission refused with a
		 * misleading message at best, and accepted wrongly at worst.
		 */
		throw new AdminError(500, `unknown setting type for ${key}`);
	}
}

/*
 * Validate the EFFECTIVE config that would become live after a restart (ApplicationConfig
 * overridden by the merged stored+submitted overrides), against the very invariants the server
 * enforces when it boots — so a super_admin cannot persist a combination that would make the next
 * startup throw.
 *
 * It calls the boot-time validator rather than restating its rules, which this used to do: a copy
 * silently drifts, and that copy had already lost the deviceFlow.charset and
 * richAuthorizationRequests.types checks. validateConfiguration is a pure function of the config
 * handed to it, so the candidate can be checked without touching the live one.
 */
function validateEffectiveConfig(effective: ConfigurationInput): void {
	try {
		validateConfiguration(effective);
	} catch (err) {
		// Every failure it raises is a TypeError describing an unrunnable configuration, which is a
		// rejected submission here, not a server fault.
		throw new AdminError(422, err instanceof Error ? err.message : String(err));
	}
}

/*
 * The state a given overrides document describes: the desired value per catalog key, and which of
 * those differ from what this process is running. Pure in `stored`, so the PUT can derive the
 * effective values it diffs a submission against without reading the store twice.
 */
function stateFor(stored: Record<string, unknown>) {
	const values: Record<string, unknown> = {};
	const changedKeys: string[] = [];
	for (const d of SETTINGS_CATALOG) {
		const run = running(d.key as string);
		const desired = Object.prototype.hasOwnProperty.call(
			stored,
			d.key as string
		)
			? stored[d.key as string]
			: run;
		values[d.key as string] = desired;
		if (!sameValue(desired, run)) changedKeys.push(d.key as string);
	}
	return {
		catalog: SETTINGS_CATALOG,
		values,
		restartRequired: changedKeys.length > 0,
		changedKeys
	};
}

async function currentState() {
	return stateFor(((await configStore.get()) ?? {}) as Record<string, unknown>);
}

/*
 * The submitted keys whose value actually differs from the one in force (the stored override if there
 * is one, otherwise what this process is running).
 *
 * The console submits the whole catalog on every Save, so without this a single toggle named every
 * setting in the audit trail — a record that says "everything changed" is not a record of anything —
 * and pinned an override for every key into the store, which quietly took the env and the defaults out
 * of the loop for keys nobody had ever edited.
 *
 * A key the catalog does not know has no value in force to compare against, so it is always kept and
 * left to validateValue to refuse: dropping it here would turn an unknown setting into a silent no-op.
 */
function realChanges(
	body: Record<string, unknown>,
	inForce: Record<string, unknown>
): Record<string, unknown> {
	const changes: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(body)) {
		if (CATALOG_BY_KEY.has(key) && sameValue(value, inForce[key])) continue;
		changes[key] = value;
	}
	return changes;
}

export const settingsRoutes = new Elysia({ name: 'admin-settings' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/settings', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return currentState();
	})
	.put(
		'/admin/api/settings',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			const stored = ((await configStore.get()) ?? {}) as Record<
				string,
				unknown
			>;
			const current = stateFor(stored);
			const changes = realChanges(body, current.values);
			// Only what is really changing is validated. A value already in force has been accepted once
			// already (or came from the environment), so restating it must not be able to refuse an edit
			// somewhere else in the same submission.
			for (const [key, value] of Object.entries(changes)) {
				const descriptor = CATALOG_BY_KEY.get(key);
				if (!descriptor) throw new AdminError(422, `unknown setting: ${key}`);
				validateValue(descriptor, value);
			}
			// Nothing to apply, so there is nothing to record: an entry here would claim a change that
			// never happened, on the one surface whose whole purpose is to be trusted about what did.
			if (Object.keys(changes).length === 0) return current;
			const merged = { ...stored, ...changes };
			// Still judged on the whole merged result, not on the changed keys alone: the invariants are
			// cross-key, so a change can only be understood next to the settings it has to agree with.
			validateEffectiveConfig({ ...ApplicationConfig, ...merged });
			// Audit-first: a persisted change must never outlive a failed audit write. The submitted keys
			// used to travel in `targetId`, which had to stand in for a field the entry did not have; the
			// target is now the settings document itself.
			await recordAdminAudit(ctx, 'settings.update', SETTINGS_TARGET_ID, {
				attributes: Object.keys(changes)
			});
			await configStore.set(merged);
			return currentState();
		},
		{ body: UpdateSettingsBody }
	);
