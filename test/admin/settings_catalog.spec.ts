import { describe, it, expect } from 'bun:test';
import { SETTINGS_CATALOG } from 'lib/admin/settings/catalog.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

describe('settings catalog', () => {
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
