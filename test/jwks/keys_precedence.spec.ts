import { describe, it, afterAll, expect } from 'bun:test';

import { agent } from '../test_helper.js';
import { provider } from 'lib/index.ts';
import { TestAdapter } from '../models.js';
import { testSigningKeys } from './fixtures.js';

const [, ecKey] = testSigningKeys;

describe('JWKS source precedence and env isolation', () => {
	afterAll(() => {
		delete process.env.JWKS;
	});

	it('uses setup.jwks over the store when provided (FR-010)', async () => {
		provider.init({
			adapter: TestAdapter,
			clients: [],
			jwks: { keys: [ecKey] }
		});

		const { data, status } = await agent.jwks.get();
		expect(status).toBe(200);
		expect(data.keys.map((k) => k.kid)).toEqual([ecKey.kid]);
	});

	it('ignores a stale JWKS environment variable (FR-002)', async () => {
		process.env.JWKS = '{"keys":[{"garbage":true}]}';

		// No jwks in setup → falls back to the store-loaded JWKS_KEYS, not the env var.
		provider.init({ adapter: TestAdapter, clients: [] });

		const { data, status } = await agent.jwks.get();
		expect(status).toBe(200);
		const publishedKids = data.keys.map((k) => k.kid).sort();
		expect(publishedKids).toEqual(testSigningKeys.map((k) => k.kid).sort());
	});
});
