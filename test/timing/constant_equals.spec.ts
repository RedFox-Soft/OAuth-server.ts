import { describe, it } from 'bun:test';

import constantEquals from 'lib/helpers/constant_equals.ts';
import { measureSeparability, expectIndistinguishable } from './harness.ts';

/*
 * The invariant the helper exists for, measured rather than asserted.
 *
 * It went unproven for as long as the helper existed, and the reason is worth keeping: the spec that
 * covered it was named "compares strings in equal time" and both its cases asserted equality RESULTS.
 * The name is what stopped anybody noticing — a file can claim a property in its title and check
 * something else entirely, and nothing in a green run says so. Recorded as G-001.
 *
 * Proved here rather than at the four call sites — dynamic client registration, PKCE verification,
 * client-secret checking, device-code lookup — because none of them has an observable timing surface
 * above it. Principle V admits an invariant below the public surface where that is the only place it
 * is observable, and names constant-time comparison as the standing example.
 */

/* Same length in both classes: length leakage is inherent to this helper's padding and is a separate
 * question. Varying it here would produce a test that fails on correct code. */
const SECRET = 'S'.repeat(64);
const DIFFERS_FIRST = `0${'S'.repeat(63)}`;
const DIFFERS_LAST = `${'S'.repeat(63)}0`;

/**
 * @proves An attacker cannot learn where a guessed secret first went wrong from how long the answer
 * takes.
 */
describe('secret comparison', () => {
	it('takes indistinguishable time whether a candidate differs at the first position or the last', () => {
		const verdict = measureSeparability(
			(candidate) => constantEquals(SECRET, candidate),
			{ early: DIFFERS_FIRST, late: DIFFERS_LAST }
		);

		expectIndistinguishable(verdict, 'secret comparison');
	});
});
