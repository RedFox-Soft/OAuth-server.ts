import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from '../../lib/configs/application.js';
import { featuresKeyMap } from '../../lib/configs/discoverySupport.js';

const endpoint = () => agent['.well-known']['openid-configuration'].get();

describe('discovery featuresKeyMap coverage', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'all_features' });
	});

	it('governs every feature-gated key through the map (no hidden handler branch)', async () => {
		const enabled = (await endpoint()).data as Record<string, unknown>;

		// Disable every governing flag at runtime; whatever disappears is feature-gated.
		for (const flag of Object.keys(featuresKeyMap)) {
			(ApplicationConfig as Record<string, unknown>)[flag] = false;
		}
		const disabled = (await endpoint()).data as Record<string, unknown>;

		const gatedKeys = Object.keys(enabled).filter((key) => !(key in disabled));
		const mapKeys = new Set(Object.values(featuresKeyMap).flat());

		expect(gatedKeys.length).toBeGreaterThan(0);
		for (const key of gatedKeys) {
			expect(
				mapKeys.has(key as never),
				`"${key}" disappeared when features were disabled but is not in featuresKeyMap`
			).toBe(true);
		}
	});
});
