import { describe, it } from 'bun:test';

import { compareClientSecret } from 'lib/models/client/secret.ts';
import { measureSeparability, expectIndistinguishable } from './harness.ts';

/*
 * The same invariant on the comparison an attacker reaches on EVERY token request.
 *
 * Its own case rather than folded into the general helper's, for two reasons the sibling file does
 * not carry. This is the hot path — `lib/shared/token_auth.ts` reaches it for every client
 * authenticating with a secret — so it is where an attacker gets the sample count a timing attack
 * needs. And it passes a `minComp` floor of 1000, which changes the shape of the work: every
 * comparison allocates and writes two 1,000-byte buffers, and that could plausibly have swamped the
 * signal. Measured separately because it could plausibly have behaved differently; it does not.
 *
 * Recorded as G-003. The case that stood here previously asserted only that the right secret matches
 * and a wrong one does not — true, and silent about time.
 */

const SECRET = 'S'.repeat(64);
const DIFFERS_FIRST = `0${'S'.repeat(63)}`;
const DIFFERS_LAST = `${'S'.repeat(63)}0`;

/* Built once, outside the measured closure, so the comparison is what gets timed. */
const client = { clientSecret: SECRET };

/**
 * @proves An attacker guessing a client secret against the token endpoint learns nothing from how
 * long the refusal takes.
 */
describe('client secret comparison', () => {
	it('takes indistinguishable time whether a candidate differs at the first position or the last', () => {
		const verdict = measureSeparability(
			(candidate) => compareClientSecret(client, candidate),
			{ early: DIFFERS_FIRST, late: DIFFERS_LAST }
		);

		expectIndistinguishable(verdict, 'client secret comparison');
	});
});
