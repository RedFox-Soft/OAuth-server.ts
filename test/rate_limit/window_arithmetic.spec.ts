import { describe, it, expect } from 'bun:test';

import {
	decide,
	type OriginCounter,
	type RateBounds
} from 'lib/helpers/rate_limit_window.js';

/*
 * The pure half of the limiter, driven entirely by a synthetic clock.
 *
 * Nothing here starts a server, reads Date.now(), or sleeps. Window expiry is the one property the
 * integration specs cannot prove without waiting, so it is proven here instead — the same split
 * lib/helpers/rate_window.ts already uses for the per-identity cooldowns.
 */
const BOUNDS: RateBounds = { max: 3, windowSeconds: 60 };

const T0 = 1_000_000;

function counter(count: number, windowStart: number): OriginCounter {
	return { count, windowStart };
}

describe('rate limit window arithmetic', () => {
	describe('a first request', () => {
		it('is never refused and opens a window at the current time', () => {
			const decision = decide(undefined, T0, BOUNDS);

			expect(decision.refused).toBe(false);
			expect(decision.next).toEqual({ count: 1, windowStart: T0 });
		});

		it('reports no retry delay when it is not refused', () => {
			expect(decide(undefined, T0, BOUNDS).retryAfterSeconds).toBe(0);
		});
	});

	describe('inside an active window', () => {
		it('counts up to the allowance without refusing', () => {
			expect(decide(counter(1, T0), T0 + 1, BOUNDS).refused).toBe(false);
			expect(decide(counter(2, T0), T0 + 2, BOUNDS).refused).toBe(false);
		});

		it('serves the request that reaches the allowance', () => {
			const decision = decide(counter(2, T0), T0 + 2, BOUNDS);

			expect(decision.refused).toBe(false);
			expect(decision.next.count).toBe(3);
		});

		it('refuses the request after the allowance is spent', () => {
			expect(decide(counter(3, T0), T0 + 3, BOUNDS).refused).toBe(true);
		});

		// A refused request that incremented would let an aggressive client extend its own penalty
		// indefinitely — an unintended permanent ban with no operator action behind it.
		it('does not charge a refused request against the counter', () => {
			const decision = decide(counter(3, T0), T0 + 3, BOUNDS);

			expect(decision.next).toEqual({ count: 3, windowStart: T0 });
		});

		it('never lets the counter exceed the allowance', () => {
			for (let elapsed = 0; elapsed < BOUNDS.windowSeconds; elapsed += 7) {
				const decision = decide(counter(3, T0), T0 + elapsed, BOUNDS);
				expect(decision.next.count).toBeLessThanOrEqual(BOUNDS.max);
			}
		});
	});

	describe('the retry delay', () => {
		it('states the time remaining in the window', () => {
			expect(decide(counter(3, T0), T0 + 20, BOUNDS).retryAfterSeconds).toBe(
				40
			);
		});

		// Rounded up rather than down: a delay shorter than the true remaining time sends a
		// well-behaved client straight into a second refusal (FR-006).
		it('never understates the wait', () => {
			for (let elapsed = 0; elapsed < BOUNDS.windowSeconds; elapsed += 1) {
				const decision = decide(counter(3, T0), T0 + elapsed, BOUNDS);
				const trueRemaining = BOUNDS.windowSeconds - elapsed;
				expect(decision.retryAfterSeconds).toBeGreaterThanOrEqual(
					trueRemaining
				);
			}
		});

		// Zero would tell a client to retry immediately, into a refusal that is still in force.
		it('is never zero on a refusal', () => {
			const atTheEdge = decide(
				counter(3, T0),
				T0 + BOUNDS.windowSeconds - 1,
				BOUNDS
			);

			expect(atTheEdge.refused).toBe(true);
			expect(atTheEdge.retryAfterSeconds).toBeGreaterThanOrEqual(1);
		});
	});

	describe('when the window has lapsed', () => {
		it('resets rather than refusing, however far over the allowance the prior count was', () => {
			const decision = decide(
				counter(99, T0),
				T0 + BOUNDS.windowSeconds,
				BOUNDS
			);

			expect(decision.refused).toBe(false);
			expect(decision.next).toEqual({
				count: 1,
				windowStart: T0 + BOUNDS.windowSeconds
			});
		});

		it('treats the boundary second as a new window, not the old one', () => {
			const lastOfOld = decide(
				counter(3, T0),
				T0 + BOUNDS.windowSeconds - 1,
				BOUNDS
			);
			const firstOfNew = decide(
				counter(3, T0),
				T0 + BOUNDS.windowSeconds,
				BOUNDS
			);

			expect(lastOfOld.refused).toBe(true);
			expect(firstOfNew.refused).toBe(false);
		});
	});

	// Called on every request ahead of routing, so a throw here is a 500 on a healthy endpoint.
	describe('totality', () => {
		it('returns a decision for any counter state and any clock value', () => {
			const states = [
				undefined,
				counter(0, T0),
				counter(1, T0),
				counter(999, T0),
				counter(1, T0 + 5_000),
				counter(-1, T0)
			];
			const clocks = [0, T0 - 1, T0, T0 + 1, T0 + 60, T0 + 10_000];

			for (const prior of states) {
				for (const now of clocks) {
					const decision = decide(prior, now, BOUNDS);
					expect(typeof decision.refused).toBe('boolean');
					expect(decision.retryAfterSeconds).toBeGreaterThanOrEqual(0);
					expect(Number.isFinite(decision.next.count)).toBe(true);
				}
			}
		});

		it('handles an allowance of one', () => {
			const tight: RateBounds = { max: 1, windowSeconds: 60 };

			expect(decide(undefined, T0, tight).refused).toBe(false);
			expect(decide(counter(1, T0), T0, tight).refused).toBe(true);
		});
	});
});
