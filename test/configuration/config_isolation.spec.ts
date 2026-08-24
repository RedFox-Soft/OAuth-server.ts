import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.js';

// bootstrap() restores ApplicationConfig from a baseline snapshot taken when test_helper loaded.
// A shallow snapshot shares every nested value with the live config, so one spec mutating a nested
// object in place poisons the baseline itself and the mutation is re-applied by every later
// bootstrap. That leak is invisible on a machine whose directory scan happens to run the mutating
// spec last, and deterministic on one where it runs first — see test/discovery/discovery_parity.
describe('ApplicationConfig isolation between specs', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('drops an in-place mutation of a nested object on the next bootstrap', async () => {
		(ApplicationConfig.discovery as Record<string, unknown>).leaked_key =
			'leaked';

		await bootstrap(import.meta.url);

		expect(ApplicationConfig.discovery).not.toHaveProperty('leaked_key');
	});

	it('drops an in-place mutation of a nested array on the next bootstrap', async () => {
		ApplicationConfig.clientAuthMethods.push('leaked_method');

		await bootstrap(import.meta.url);

		expect(ApplicationConfig.clientAuthMethods).not.toContain('leaked_method');
	});
});
