import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SETTINGS_CATALOG } from 'lib/admin/settings/catalog.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

describe('settings catalog', () => {
	/*
	 * The nonce secret's absence from the catalog is what makes it unreachable from the admin API,
	 * which filters submissions against this list. The absence is already pinned below; this pins the
	 * *reason* being written down next to it, so a later reader finds a decision rather than a hole
	 * they might helpfully fill in. Reading the module's source is the only way to assert a comment
	 * exists — the same technique test/storage_contract/inventory_drift.spec.ts uses on lib sources.
	 */
	it('records in the module why the DPoP nonce secret is not an operator setting', () => {
		const source = readFileSync(
			resolve(import.meta.dir, '../../lib/admin/settings/catalog.ts'),
			'utf8'
		);

		expect(source).toContain('dpop.nonceSecret');
		expect(source).toMatch(/server-provisioned|server-owned/);
	});

	it('every catalog key exists in ApplicationConfig', () => {
		for (const d of SETTINGS_CATALOG) {
			expect(
				Object.prototype.hasOwnProperty.call(ApplicationConfig, d.key)
			).toBe(true);
		}
	});

	it('descriptors are well-formed and keys are unique', () => {
		const seen = new Set<string>();
		for (const d of SETTINGS_CATALOG) {
			expect(seen.has(d.key)).toBe(false);
			seen.add(d.key);
			expect(d.group.length).toBeGreaterThan(0);
			expect(d.label.length).toBeGreaterThan(0);
			expect(['boolean', 'string', 'enum', 'string-array']).toContain(d.type);
			if (d.type === 'enum') expect(Array.isArray(d.options)).toBe(true);
		}
	});

	it('exposes authorization.allowOmittingSingleRegisteredRedirectUri as a boolean in the Authorization group', () => {
		const d = SETTINGS_CATALOG.find(
			(x) => x.key === 'authorization.allowOmittingSingleRegisteredRedirectUri'
		);
		expect(d).toBeDefined();
		expect(d?.type).toBe('boolean');
		expect(d?.group).toBe('Authorization');
	});

	it('exposes conformIdTokenClaims as a boolean in the ID Token group', () => {
		const d = SETTINGS_CATALOG.find((x) => x.key === 'conformIdTokenClaims');
		expect(d).toBeDefined();
		expect(d?.type).toBe('boolean');
		expect(d?.group).toBe('ID Token');
		expect(d?.dependsOn).toBeUndefined();
	});

	it('exposes cors.enabled as a boolean in its own group', () => {
		const d = SETTINGS_CATALOG.find((x) => x.key === 'cors.enabled');
		expect(d).toBeDefined();
		expect(d?.type).toBe('boolean');
		expect(d?.group).toBe('CORS');
		// No parent flag: the switch stands alone, and closure otherwise comes from project data.
		expect(d?.dependsOn).toBeUndefined();
	});

	/*
	 * cors.maxAge was considered and dropped: it would be the first numeric key in ApplicationConfig and
	 * SettingType has no `number` member, so it could only be written by editing serviceConfig directly
	 * — the admin PUT filters by this catalog. Pinned so adding the key without a type is a test failure
	 * rather than an unreachable setting.
	 */
	it('declares no numeric setting, and no cors.maxAge companion', () => {
		expect(SETTINGS_CATALOG.map((d) => d.key)).not.toContain('cors.maxAge');
		expect(
			Object.prototype.hasOwnProperty.call(ApplicationConfig, 'cors.maxAge')
		).toBe(false);
	});

	it('excludes structured/function/Buffer keys', () => {
		const keys = SETTINGS_CATALOG.map((d) => d.key);
		for (const forbidden of [
			'claims',
			// discovery lives on ApplicationConfig but is deliberately not operator-editable:
			// it is relocated, not exposed. Absence from the catalog is the whole enforcement.
			'discovery',
			'registration.policies',
			'registration.initialAccessToken',
			'richAuthorizationRequests.types',
			'dpop.nonceSecret'
		]) {
			expect(keys).not.toContain(forbidden);
		}
	});

	// A draft-spec feature is surfaced as information on the setting that enables it. There is no
	// acknowledgement setting and no boot-time notice: an operator sees the tag in the admin UI,
	// and nothing about the server's behaviour depends on it.
	it('marks a draft-spec feature experimental, and only informationally', () => {
		const rar = SETTINGS_CATALOG.find(
			(d) => d.key === 'richAuthorizationRequests.enabled'
		);
		expect(rar?.experimental).toBe(true);

		// Nothing else claims to be experimental, so the tag stays meaningful.
		const experimental = SETTINGS_CATALOG.filter((d) => d.experimental).map(
			(d) => d.key
		);
		expect(experimental).toEqual(['richAuthorizationRequests.enabled']);

		// The retired acknowledgement setting is gone from the settings themselves, not just hidden
		// from the catalog.
		expect(
			Object.prototype.hasOwnProperty.call(
				ApplicationConfig,
				'richAuthorizationRequests.ack'
			)
		).toBe(false);
	});

	it('declared enum/option values match the ApplicationConfig defaults domain', () => {
		const charset = SETTINGS_CATALOG.find(
			(d) => d.key === 'deviceFlow.charset'
		);
		expect(charset?.options).toEqual(['base-20', 'digits']);
		const delivery = SETTINGS_CATALOG.find(
			(d) => d.key === 'ciba.deliveryModes'
		);
		expect(delivery?.options).toEqual(['poll', 'ping']);
	});

	it('every dependsOn references a boolean catalog key in the same group', () => {
		const byKey = new Map(SETTINGS_CATALOG.map((d) => [d.key, d]));
		const details = SETTINGS_CATALOG.filter((d) => d.dependsOn);
		expect(details.length).toBeGreaterThan(0);
		for (const d of details) {
			expect(
				Object.prototype.hasOwnProperty.call(
					ApplicationConfig,
					d.dependsOn as string
				)
			).toBe(true);
			const parent = byKey.get(d.dependsOn as keyof typeof ApplicationConfig);
			expect(parent).toBeDefined();
			expect(parent?.type).toBe('boolean');
			expect(parent?.group).toBe(d.group);
			expect(parent?.dependsOn).toBeUndefined(); // parents are primaries
		}
	});
});
