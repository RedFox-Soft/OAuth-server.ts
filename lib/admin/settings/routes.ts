import { Elysia } from 'elysia';
import { ApplicationConfig } from '../../configs/application.js';
import { configStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
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
			throw new AdminError(422, `${key} must be one of: ${options?.join(', ')}`);
	} else {
		// string-array
		if (!Array.isArray(value) || !value.every((v) => typeof v === 'string'))
			throw new AdminError(422, `${key} must be an array of strings`);
		if (options && !value.every((v) => options.includes(v as string)))
			throw new AdminError(422, `${key} values must be among: ${options.join(', ')}`);
		if (key === 'scopes' && !value.includes('openid'))
			throw new AdminError(422, 'scopes must include "openid"');
	}
}

// Validate the EFFECTIVE config that would become live after a restart (ApplicationConfig
// overridden by the merged stored+submitted overrides). Mirrors the invariants enforced at
// boot in lib/helpers/configuration.ts (checkCibaDeliveryModes, checkDeviceFlow,
// checkDependantFeatures) so a super_admin cannot persist a combination that would throw a
// TypeError when the provider is constructed on next startup. Throws AdminError(422).
function validateEffectiveConfig(effective: Record<string, unknown>): void {
	// mirrors Configuration#checkCibaDeliveryModes (lib/helpers/configuration.ts)
	const deliveryModes = effective['ciba.deliveryModes'];
	if (!Array.isArray(deliveryModes) || !deliveryModes.length) {
		throw new AdminError(422, 'features.ciba.deliveryModes must not be empty');
	}

	// mirrors Configuration#checkDeviceFlow (lib/helpers/configuration.ts)
	if (effective['deviceFlow.enabled']) {
		const mask = effective['deviceFlow.mask'];
		if (typeof mask !== 'string' || !/^[-* ]*$/.test(mask)) {
			throw new AdminError(
				422,
				'mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters'
			);
		}
	}

	// mirrors Configuration#checkDependantFeatures (lib/helpers/configuration.ts)
	if (effective['jwtIntrospection.enabled'] && !effective['introspection.enabled']) {
		throw new AdminError(
			422,
			'jwtIntrospection is only available in conjuction with introspection'
		);
	}
	if (effective['jwtUserinfo.enabled'] && !effective['userinfo.enabled']) {
		throw new AdminError(
			422,
			'jwtUserinfo is only available in conjuction with userinfo'
		);
	}
	if (
		effective['registrationManagement.enabled'] &&
		!effective['registration.enabled']
	) {
		throw new AdminError(
			422,
			'registrationManagement is only available in conjuction with registration'
		);
	}
	if (
		effective['richAuthorizationRequests.enabled'] &&
		!effective['resourceIndicators.enabled']
	) {
		throw new AdminError(
			422,
			'richAuthorizationRequests is only available in conjuction with enabled resourceIndicators'
		);
	}
}

async function currentState() {
	const stored = (await configStore.get()) ?? {};
	const values: Record<string, unknown> = {};
	const changedKeys: string[] = [];
	for (const d of SETTINGS_CATALOG) {
		const run = running(d.key as string);
		const desired = Object.prototype.hasOwnProperty.call(stored, d.key as string)
			? (stored as Record<string, unknown>)[d.key as string]
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

export const settingsRoutes = new Elysia({ name: 'admin-settings' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
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
			for (const [key, value] of Object.entries(body)) {
				const descriptor = CATALOG_BY_KEY.get(key);
				if (!descriptor) throw new AdminError(422, `unknown setting: ${key}`);
				validateValue(descriptor, value);
			}
			const stored = (await configStore.get()) ?? {};
			const merged = { ...stored, ...body };
			validateEffectiveConfig({ ...ApplicationConfig, ...merged });
			await configStore.set(merged);
			return currentState();
		},
		{ body: UpdateSettingsBody }
	);
