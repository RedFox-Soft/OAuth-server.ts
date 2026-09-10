import { describe, it, expect } from 'bun:test';

import { STORAGE_DIVERGENCES } from 'lib/consts/storage_divergences.js';

/*
 * The register's own rules, checked here rather than in `database/verify_postgres.ts`.
 *
 * The fidelity script is the only tier with no gate on it — nothing fails when a check is added
 * there, so it collects work that belongs elsewhere. These assertions need no database, so under
 * Principle III's second binding condition they do not belong in a tier reserved for what a
 * hermetic test cannot reach. What stays in the script is the part that needs a real PostgreSQL:
 * observing a difference and failing when it is not listed here.
 *
 * The two content rules are the ones that decide whether the register is worth reading. `reason`
 * must say why converging is worse than differing rather than restating the difference, and
 * `observable` must say what a caller could notice — an entry whose honest answer is "nothing" is
 * still legitimate (a convergence recorded so it stays visible), but it has to say so in words
 * rather than by being blank.
 */

describe('the storage divergence register', () => {
	it('declares entries at all, so the rules below cannot pass vacuously', () => {
		expect(STORAGE_DIVERGENCES.length).toBeGreaterThan(0);
	});

	it('gives every entry a unique id', () => {
		const ids = STORAGE_DIVERGENCES.map((d) => d.id);

		expect(ids.length).toBe(new Set(ids).size);
	});

	it('says what each backend does, for both of them', () => {
		const silent = STORAGE_DIVERGENCES.filter(
			(d) => !d.mongodb.trim() || !d.postgres.trim() || !d.subject.trim()
		).map((d) => d.id);

		expect(silent).toEqual([]);
	});

	it('states a reason and what is observable, in sentences rather than labels', () => {
		// The length floor is crude and deliberate: it is not a quality bar, it is a bar against an
		// entry added in a hurry with `reason: 'differs'` to get a red run green.
		const thin = STORAGE_DIVERGENCES.filter(
			(d) => d.reason.trim().length < 40 || d.observable.trim().length < 40
		).map((d) => d.id);

		expect(thin).toEqual([]);
	});
});
