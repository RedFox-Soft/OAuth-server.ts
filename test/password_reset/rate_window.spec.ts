import { describe, it, expect } from 'bun:test';

import {
	rateRefusal,
	nextRateFields,
	type RateBounds,
	type RateFields
} from 'lib/helpers/rate_window.js';

// The arithmetic behind "how often can one address be made to receive a security email", shared by the
// verification resend and the password reset (specs/020-enduser-password-reset, research D2). Pure
// functions, so they are tested directly rather than through two HTTP surfaces that would each prove half
// of it.

const bounds: RateBounds = {
	cooldownSeconds: 60,
	cap: 5,
	windowSeconds: 24 * 60 * 60
};

const NOW = 1_000_000;

function prior(fields: Partial<RateFields> = {}): RateFields {
	return {
		lastSentAt: NOW,
		dayCount: 1,
		windowStart: NOW,
		...fields
	};
}

describe('rate window: refusal', () => {
	it('permits a send when nothing has been sent before', () => {
		expect(rateRefusal(undefined, NOW, bounds)).toBeNull();
	});

	it('refuses inside the cooldown', () => {
		expect(rateRefusal(prior(), NOW + 59, bounds)).toBe('cooldown');
	});

	it('permits once the cooldown has elapsed', () => {
		expect(rateRefusal(prior(), NOW + 60, bounds)).toBeNull();
	});

	// Cooldown is checked first deliberately: at the cap *and* inside the cooldown, the honest answer is
	// the one that will stop being true in a minute.
	it('reports the cooldown ahead of the cap', () => {
		const atCap = prior({ dayCount: 5 });

		expect(rateRefusal(atCap, NOW + 1, bounds)).toBe('cooldown');
	});

	it('refuses at the cap while the window is still open', () => {
		const atCap = prior({ dayCount: 5 });

		expect(rateRefusal(atCap, NOW + 120, bounds)).toBe('daily');
	});

	it('permits again once the window has rolled past', () => {
		const atCap = prior({ dayCount: 5 });

		expect(rateRefusal(atCap, NOW + bounds.windowSeconds, bounds)).toBeNull();
	});

	it('permits below the cap', () => {
		const belowCap = prior({ dayCount: 4 });

		expect(rateRefusal(belowCap, NOW + 120, bounds)).toBeNull();
	});
});

describe('rate window: next fields', () => {
	it('opens a window on the first send', () => {
		expect(nextRateFields(undefined, NOW, bounds, true)).toEqual({
			lastSentAt: NOW,
			dayCount: 1,
			windowStart: NOW
		});
	});

	it('increments within the open window and keeps its start', () => {
		expect(
			nextRateFields(prior({ dayCount: 2 }), NOW + 300, bounds, true)
		).toEqual({
			lastSentAt: NOW + 300,
			dayCount: 3,
			windowStart: NOW
		});
	});

	it('opens a fresh window once the old one has expired', () => {
		const later = NOW + bounds.windowSeconds + 1;

		expect(nextRateFields(prior({ dayCount: 5 }), later, bounds, true)).toEqual(
			{
				lastSentAt: later,
				dayCount: 1,
				windowStart: later
			}
		);
	});

	// `bump: false` is the verification flow's initial registration send, which deliberately does not
	// spend the window. The reset flow never passes it — there is no "initial" reset.
	it('carries the counters over unchanged when the send does not count', () => {
		expect(
			nextRateFields(prior({ dayCount: 3 }), NOW + 300, bounds, false)
		).toEqual({
			lastSentAt: NOW,
			dayCount: 3,
			windowStart: NOW
		});
	});

	it('carries over a zeroed state when there is no prior and the send does not count', () => {
		expect(nextRateFields(undefined, NOW, bounds, false)).toEqual({
			lastSentAt: 0,
			dayCount: 0,
			windowStart: NOW
		});
	});
});
