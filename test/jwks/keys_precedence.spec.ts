import { describe, it, afterAll, expect } from 'bun:test';

import bootstrap, { agent, seedJwks } from '../test_helper.js';
import { testSigningKeys } from './fixtures.js';

const [, ecKey] = testSigningKeys;

// The former "uses setup.jwks over the store" case is gone with the capability it asserted: keys
// are single-sourced from the jwksStore adapter (as clients are from the Client store), so there is
// no per-instance key input left for the store to take precedence over. What remains worth pinning
// is that the store — and only the store — decides the published set.
describe('JWKS source is the store, and only the store', () => {
	afterAll(async () => {
		delete process.env.JWKS;
		// Leave the shared fixture set behind for whatever runs next.
		await seedJwks(testSigningKeys);
	});

	it('publishes exactly what the store holds', async () => {
		await bootstrap(import.meta.url, { config: 'store' });
		// seedJwks reloads the key set and rebuilds the published JWKS on its own; there is no
		// provider step to re-run afterwards.
		await seedJwks([ecKey]);

		const { data, status } = await agent.jwks.get();
		if (!data) throw new Error('expected response data');
		expect(status).toBe(200);
		expect(data.keys.map((k) => k.kid)).toEqual([ecKey.kid]);
	});

	it('ignores a stale JWKS environment variable (FR-002)', async () => {
		process.env.JWKS = '{"keys":[{"garbage":true}]}';

		await bootstrap(import.meta.url, { config: 'store' });

		const { data, status } = await agent.jwks.get();
		if (!data) throw new Error('expected response data');
		expect(status).toBe(200);
		const publishedKids = data.keys.map((k) => k.kid).sort();
		expect(publishedKids).toEqual(testSigningKeys.map((k) => k.kid).sort());
	});
});
