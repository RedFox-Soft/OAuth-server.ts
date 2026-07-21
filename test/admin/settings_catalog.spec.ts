import { describe, it, expect } from 'bun:test';
import { SETTINGS_CATALOG } from 'lib/admin/settings/catalog.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

describe('settings catalog', () => {
	it('every catalog key exists in ApplicationConfig', () => {
		for (const d of SETTINGS_CATALOG) {
			expect(Object.prototype.hasOwnProperty.call(ApplicationConfig, d.key)).toBe(
				true
			);
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

	it('excludes structured/function/Buffer keys', () => {
		const keys = SETTINGS_CATALOG.map((d) => d.key);
		for (const forbidden of [
			'claims',
			'registration.policies',
			'registration.initialAccessToken',
			'richAuthorizationRequests.types',
			'richAuthorizationRequests.ack',
			'dpop.nonceSecret'
		]) {
			expect(keys).not.toContain(forbidden);
		}
	});

	it('declared enum/option values match the ApplicationConfig defaults domain', () => {
		const charset = SETTINGS_CATALOG.find((d) => d.key === 'deviceFlow.charset');
		expect(charset?.options).toEqual(['base-20', 'digits']);
		const delivery = SETTINGS_CATALOG.find((d) => d.key === 'ciba.deliveryModes');
		expect(delivery?.options).toEqual(['poll', 'ping']);
	});
});
