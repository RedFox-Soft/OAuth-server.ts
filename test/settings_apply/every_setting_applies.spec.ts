import { describe, it, expect, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configStore } from 'lib/adapters/index.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import {
	SETTINGS_CATALOG,
	type SettingDescriptor
} from 'lib/admin/settings/catalog.js';
import { saveSettings, superAdminCookie } from './helpers.js';

/*
 * A second value for the settings whose type does not imply one. Spelled out rather than generated,
 * because a generated `string-array` or `json` value is either the one the server already holds or one
 * it rightly refuses, and neither says anything about applying.
 */
const ALTERNATIVES: Record<string, unknown> = {
	'deviceFlow.charset': 'digits',
	'deviceFlow.mask': '****-****-****',
	'ciba.deliveryModes': ['poll', 'ping'],
	/* Empty by default — the server cannot know what else lives in an operator's domain — so the second
	 * value has to be a name rather than a shorter list. */
	'buckets.reservedHostnames': ['status.example.test'],
	'errorStore.originCaptureLevel': 'full',
	'richAuthorizationRequests.types': {
		'https://example.test/type': { label: 'Example' }
	},
	scopes: ['openid'],
	acrValues: { password: 'pwd', multi_factor: 'mfa', federated: 'fed' },
	clientAuthMethods: ['client_secret_basic', 'none']
};

/*
 * What has to travel with a setting for the result to be runnable, where the descriptor's own
 * `dependsOn` does not already say so. Rich authorization requests is the one case: with no declared
 * type every authorization_details value is rejected before any hook runs, so the validator refuses
 * the combination — the capability and its types are one decision.
 */
const COMPANIONS: Record<string, Record<string, unknown>> = {
	'richAuthorizationRequests.enabled': {
		'richAuthorizationRequests.types': {
			'https://example.test/type': { label: 'Example' }
		},
		'resourceIndicators.enabled': true
	},
	'registrationManagement.enabled': { 'registration.enabled': true },
	'jwtIntrospection.enabled': { 'introspection.enabled': true },
	'jwtUserinfo.enabled': { 'userinfo.enabled': true }
};

/*
 * Settings no submission can exercise on its own, with the reason. Each one needs a value that is not
 * itself an operator setting, so a case driving only the catalog cannot reach a runnable combination.
 */
const NOT_EXERCISABLE_ALONE: Record<string, string> = {
	'sentry.enabled':
		'reporting requires an ingestion credential, which is deliberately absent from the catalog and is written through the Sentry card instead'
};

function alternativeFor(d: SettingDescriptor): unknown {
	const key = d.key as string;
	if (Object.prototype.hasOwnProperty.call(ALTERNATIVES, key)) {
		return ALTERNATIVES[key];
	}
	const current = (ApplicationConfig as Record<string, unknown>)[key];
	if (d.type === 'boolean') {
		return !current;
	}
	if (d.type === 'number') {
		return (current as number) + 1;
	}
	if (d.type === 'enum') {
		return d.options?.find((option) => option !== current);
	}
	return undefined;
}

/**
 * @proves Every setting an operator can edit and is told applies when saved does reach the running
 * server — the claim being that the value is in force, which is what the console reports, and not
 * that every consumer of it re-read it, which the cases beside this one prove for real behaviour.
 */
describe('the settings an operator is told take effect when saved', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await configStore.set({});
		cookie = await superAdminCookie();
	});

	it('each leave the stored and the in-force value equal after a save', async () => {
		const applied: string[] = [];

		for (const d of SETTINGS_CATALOG) {
			const key = d.key as string;
			if (d.apply === 'restart') {
				continue;
			}
			if (Object.prototype.hasOwnProperty.call(NOT_EXERCISABLE_ALONE, key)) {
				continue;
			}

			const before = (ApplicationConfig as Record<string, unknown>)[key];
			const next = alternativeFor(d);
			expect(
				next,
				`no second value known for ${key}; add one to ALTERNATIVES`
			).toBeDefined();

			const change: Record<string, unknown> = { [key]: next };
			const restore: Record<string, unknown> = { [key]: before };
			/*
			 * A setting gated by another cannot be turned on alone, and the descriptor already says
			 * which one — so the parent travels with it rather than being listed as an exception.
			 */
			if (d.dependsOn && next === true) {
				const parent = d.dependsOn as string;
				restore[parent] = (ApplicationConfig as Record<string, unknown>)[
					parent
				];
				change[parent] = true;
			}
			for (const [companion, value] of Object.entries(COMPANIONS[key] ?? {})) {
				restore[companion] = (ApplicationConfig as Record<string, unknown>)[
					companion
				];
				change[companion] = value;
			}

			const res = await saveSettings(cookie, change);
			expect(res.status, `${key} was refused`).toBe(200);

			const body = (await res.json()) as {
				appliedKeys: string[];
				notInForceKeys: string[];
				values: Record<string, unknown>;
			};
			expect(body.appliedKeys, `${key} did not take effect`).toContain(key);
			expect(body.notInForceKeys).toEqual([]);
			expect((ApplicationConfig as Record<string, unknown>)[key]).toEqual(next);

			applied.push(key);
			expect((await saveSettings(cookie, restore)).status).toBe(200);
		}

		// The set is enumerated from the catalog, so this only guards against an empty sweep.
		expect(applied.length).toBeGreaterThan(0);
	});
});
