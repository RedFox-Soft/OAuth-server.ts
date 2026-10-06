import { describe, it, beforeAll, expect } from 'bun:test';
import fc from 'fast-check';

import { getUserStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';

/**
 * @proves For every population and every page size, reading a bucket page by page yields each user
 * exactly once and reports the whole population — what a provisioning client importing a bucket
 * depends on (spec 069, FR-017, SC-003).
 */
describe('reading a bucket page by page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('yields every user exactly once and the population as the total', async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.integer({ min: 0, max: 60 }),
				fc.integer({ min: 1, max: 1000 }),
				async (population, pageSize) => {
					const store = getUserStore(`p-${nanoid()}`);
					const ids = new Set<string>();
					for (let i = 0; i < population; i += 1) {
						ids.add((await store.create(`${i}@x.io`, 'hash', [], true))._id);
					}

					const seen: string[] = [];
					let total = -1;
					for (let start = 1; start <= population; start += pageSize) {
						const page = await store.query(
							{},
							{ startIndex: start, count: pageSize }
						);
						total = page.totalResults;
						seen.push(...page.users.map((user) => user._id));
					}

					expect(seen.sort()).toEqual([...ids].sort());
					if (population > 0) expect(total).toBe(population);
				}
			),
			{ numRuns: 40 }
		);
	});
});
