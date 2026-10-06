import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SETTINGS_CATALOG, appliesOnSave } from 'lib/admin/settings/catalog.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { present } from 'test/shape.js';

/**
 * @proves Every operator-editable setting exists, is described, and carries the argument for
 * being editable at all - and the ones deliberately absent say why.
 */
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
			expect([
				'boolean',
				'string',
				'enum',
				'number',
				'string-array',
				'json'
			]).toContain(d.type);
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

	/*
	 * The console tells an operator a setting is in force the moment it is saved unless its descriptor
	 * says `apply: 'restart'`. Seven descriptions still ended "Applied at startup." long after every
	 * one of them was made to apply on save — so the only text an operator reads said the opposite of
	 * what the server does, and nothing noticed.
	 */
	it('describes no setting that applies on save as needing a restart', () => {
		const claimsRestart =
			/applied at startup|after (a |the next )?restart|requires? a restart|on (the next )?restart/i;
		const contradicted = SETTINGS_CATALOG.filter(
			(d) => d.apply !== 'restart' && claimsRestart.test(d.description)
		).map((d) => d.key);
		expect(contradicted).toEqual([]);
	});

	it('excludes structured/function/Buffer keys', () => {
		const keys = SETTINGS_CATALOG.map((d) => d.key);
		for (const forbidden of [
			// discovery lives on ApplicationConfig but is deliberately not operator-editable:
			// it is relocated, not exposed. Absence from the catalog is the whole enforcement.
			'discovery',
			'registration.policies',
			'registration.initialAccessToken',
			'dpop.nonceSecret'
		]) {
			expect(keys).not.toContain(forbidden);
		}
	});

	/*
	 * richAuthorizationRequests.types was on the forbidden list above while it was function-valued —
	 * which is exactly why the feature could not be configured by an operator at all. It is now a
	 * serializable descriptor map, so it is exposed deliberately, as the catalog's first `json` entry.
	 * Classified explicitly rather than simply dropped from the list, so the key-diff guarantee stays
	 * enforced instead of quietly weakening.
	 */
	it('exposes richAuthorizationRequests.types as a structured json setting', () => {
		const types = SETTINGS_CATALOG.find(
			(d) => d.key === 'richAuthorizationRequests.types'
		);
		expect(types?.type).toBe('json');
		expect(types?.dependsOn).toBe('richAuthorizationRequests.enabled');
	});

	/*
	 * `claims` sat on the forbidden list above with no reason recorded, and so the scopes an operator
	 * advertises could not be given any claims to release from the console or an agent — `profile`,
	 * `email` and the rest existed only for whoever could edit the database. Its value is a plain map,
	 * so it is exposed the way richAuthorizationRequests.types was: explicitly, as `json`.
	 */
	it('exposes claims as a structured json setting', () => {
		const claims = SETTINGS_CATALOG.find((d) => d.key === 'claims');
		expect(claims?.type).toBe('json');
	});

	/*
	 * RAR was the last entry marked experimental, and it tracked a draft. RFC 9396 has been published
	 * since May 2023 and the implementation now conforms to it within a recorded boundary, so the tag
	 * and the "behaviour may change" sentence are gone. The `experimental` field itself is kept as
	 * catalog vocabulary for the next feature tracked from a draft — this test pins that nothing claims
	 * it today, so the tag cannot rot back into place unnoticed.
	 */
	it('claims no draft-spec feature, and cites the published RFC for RAR', () => {
		const rar = SETTINGS_CATALOG.find(
			(d) => d.key === 'richAuthorizationRequests.enabled'
		);
		expect(rar?.experimental).toBeUndefined();
		expect(rar?.description).toContain('RFC 9396');
		expect(rar?.description).not.toContain('draft');

		const experimental = SETTINGS_CATALOG.filter((d) => d.experimental).map(
			(d) => d.key
		);
		expect(experimental).toEqual([]);
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

	/*
	 * An operator is told which settings interrupt service, and that answer has to exist for every
	 * setting rather than for the ones somebody remembered. Absence of `apply` is the permissive
	 * answer, so the property here is that the answer is total and that the restrictive one is
	 * argued: a warning with no reason beside it is the warning an operator learns to click past.
	 */
	it('every setting states whether it takes effect when saved, and every exception states why', () => {
		for (const d of SETTINGS_CATALOG) {
			expect(appliesOnSave(d.key)).toBe(d.apply !== 'restart');
			if (d.apply === 'restart') {
				expect(d.restartReason?.trim()).toBeTruthy();
			} else {
				expect(d.restartReason).toBeUndefined();
			}
		}
	});

	it('every dependsOn references a boolean catalog key in the same group', () => {
		const byKey = new Map(SETTINGS_CATALOG.map((d) => [d.key, d]));
		const details = SETTINGS_CATALOG.filter((d) => d.dependsOn);
		expect(details.length).toBeGreaterThan(0);
		for (const d of details) {
			const parentKey = present(d.dependsOn, `a dependsOn on ${d.key}`);
			expect(
				Object.prototype.hasOwnProperty.call(ApplicationConfig, parentKey)
			).toBe(true);
			const parent = byKey.get(parentKey);
			expect(parent).toBeDefined();
			expect(parent?.type).toBe('boolean');
			expect(parent?.group).toBe(d.group);
			expect(parent?.dependsOn).toBeUndefined(); // parents are primaries
		}
	});
});
