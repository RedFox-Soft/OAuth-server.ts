import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
	alwaysAvailableRoutes,
	rateRoutes
} from 'lib/consts/route_classification.js';

/*
 * The liveness route answers for the process and nothing else.
 *
 * `readiness.spec.ts` beside this file proves the behaviour — `/health` still answers 200 while the
 * storage probe rejects. This proves the two properties that keep it that way and would otherwise be
 * re-derived by whoever next edits the route: that the module reaches no storage at all, and that its
 * rate exemption has not spread to the route that does.
 *
 * The exemption is the reason the first property matters. An unmetered route is safe only while it
 * costs nothing to serve; the moment liveness touched the datastore it would be an unauthenticated
 * amplifier onto it, which is precisely why `/ready` is metered as `public` instead.
 */

const HEALTH = resolve(import.meta.dir, '../../lib/actions/health.ts');

/**
 * @proves Liveness answers from the process alone and readiness from storage, so a database
 * outage is not read as a dead process.
 */
describe('liveness and readiness are separate probes', () => {
	it('serves liveness from a module that imports no storage', () => {
		const source = readFileSync(HEALTH, 'utf8');
		const imports = [...source.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1]);

		expect(imports.length).toBeGreaterThan(0);
		expect(
			imports.filter((from) => /adapter|models|storage/i.test(from))
		).toEqual([]);
	});

	it('keeps liveness exempt from the rate limiter and readiness metered', () => {
		const rateOf = (path: string) =>
			rateRoutes.find((r) => r.path === path && r.method === 'GET')?.rate;

		expect(rateOf('/health')).toBe('exempt');
		expect(rateOf('/ready')).toBe('public');
	});

	it('serves both regardless of which capabilities are switched on', () => {
		const available = alwaysAvailableRoutes
			.filter((r) => r.method === 'GET')
			.map((r) => r.path);

		expect(available).toContain('/health');
		expect(available).toContain('/ready');
	});
});
