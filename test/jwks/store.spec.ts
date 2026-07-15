import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { testSigningKeys } from './fixtures.js';

const contentType = 'application/jwk-set+json; charset=utf-8';

describe('/jwks sourced from the store (no config.jwks)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'store' });
	});

	it('publishes every store-seeded key (public components only)', async () => {
		const { data, status, response } = await agent.jwks.get();
		if (!data) throw new Error('expected response data');

		expect(status).toBe(200);
		expect(response.headers.get('content-type')).toBe(contentType);

		const publishedKids = data.keys.map((k) => k.kid).sort();
		const seededKids = testSigningKeys.map((k) => k.kid).sort();
		expect(publishedKids).toEqual(seededKids);
	});

	it('never exposes private key components', async () => {
		const { data } = await agent.jwks.get();
		if (!data) throw new Error('expected response data');

		for (const key of data.keys) {
			for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
				expect(key).not.toHaveProperty(priv);
			}
		}
	});
});
