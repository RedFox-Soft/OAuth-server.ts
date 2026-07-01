import { describe, it, beforeAll } from 'bun:test';
import { expect } from 'chai';

import bootstrap, { agent } from '../test_helper.js';
import baseline from './__fixtures__/discovery-baseline.json';

// Order-independent normalization: discovery values are scalars or flat string arrays, so
// sorting arrays and keys makes semantic equality insensitive to insertion order.
function normalize(obj: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) {
		const value = obj[key];
		out[key] = Array.isArray(value) ? [...value].sort() : value;
	}
	return out;
}

describe('discovery parity', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'discovery_parity' })();
	});

	it('produces a document semantically identical to the pre-refactor baseline', async () => {
		const { data } = await agent['.well-known']['openid-configuration'].get();

		expect(normalize(data as Record<string, unknown>)).to.deep.equal(
			normalize(baseline as Record<string, unknown>)
		);
	});
});
