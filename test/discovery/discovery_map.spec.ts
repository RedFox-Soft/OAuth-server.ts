import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from '../../lib/configs/application.js';
import {
	featuresKeyMap,
	isFeatureFlag
} from '../../lib/configs/discoverySupport.js';
import { present } from '../shape.js';

const endpoint = async () =>
	present(
		(await agent['.well-known']['openid-configuration'].get()).data,
		'the discovery document'
	);

/**
 * @proves Every feature-gated discovery key is governed through the map, with no hidden branch
 * in the handler.
 */
describe('discovery featuresKeyMap coverage', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'all_features' });
	});

	it('governs every feature-gated key through the map (no hidden handler branch)', async () => {
		const enabled = await endpoint();

		// Disable every governing flag at runtime; whatever disappears is feature-gated.
		for (const flag of Object.keys(featuresKeyMap).filter(isFeatureFlag)) {
			ApplicationConfig[flag] = false;
		}
		const disabled = await endpoint();

		const gatedKeys = Object.keys(enabled).filter((key) => !(key in disabled));
		const mapKeys = new Set<string | undefined>(
			Object.values(featuresKeyMap).flat()
		);

		expect(gatedKeys.length).toBeGreaterThan(0);
		for (const key of gatedKeys) {
			expect(
				mapKeys.has(key),
				`"${key}" disappeared when features were disabled but is not in featuresKeyMap`
			).toBe(true);
		}
	});
});
