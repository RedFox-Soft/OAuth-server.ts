/*
 * The arithmetic behind "how often can one address be made to receive a security email" — shared by the
 * email-verification resend and the password-reset request.
 *
 * Shared because it is a security rule, and two hand-maintained copies of a security rule answer the
 * question differently after the first edit. Only the arithmetic is shared: the bounds, the storage area,
 * and whether a given send counts against the window stay with each flow, because that is where the two
 * genuinely differ — verification's initial registration send deliberately does not spend the window,
 * while every reset request does.
 *
 * Pure by construction: no clock, no adapter, no constants of its own. `now` is passed in so a caller
 * reads the clock once per operation and a test needs no fake one.
 */

export interface RateBounds {
	/* Minimum gap between two sends. */
	readonly cooldownSeconds: number;
	/* Sends allowed inside one window. */
	readonly cap: number;
	/* Length of the rolling window the cap is measured over. */
	readonly windowSeconds: number;
}

export interface RateFields {
	readonly lastSentAt: number;
	readonly dayCount: number;
	readonly windowStart: number;
}

export type RateRefusal = 'cooldown' | 'daily';

/*
 * Why this send is refused, or null when it may proceed.
 *
 * Cooldown is checked before the cap deliberately: when both apply, the honest answer is the one that
 * stops being true in a minute.
 */
export function rateRefusal(
	prior: RateFields | undefined,
	now: number,
	bounds: RateBounds
): RateRefusal | null {
	if (!prior) {
		return null;
	}
	if (now - prior.lastSentAt < bounds.cooldownSeconds) {
		return 'cooldown';
	}
	const windowActive = now - prior.windowStart < bounds.windowSeconds;
	if (windowActive && prior.dayCount >= bounds.cap) {
		return 'daily';
	}
	return null;
}

/*
 * The counters after a send. With `bump` unset the counters are carried over unchanged — the caller is
 * writing the record for some other reason and this send is not to be charged for.
 */
export function nextRateFields(
	prior: RateFields | undefined,
	now: number,
	bounds: RateBounds,
	bump: boolean
): RateFields {
	if (!bump) {
		return {
			lastSentAt: prior?.lastSentAt ?? 0,
			dayCount: prior?.dayCount ?? 0,
			windowStart: prior?.windowStart ?? now
		};
	}

	const windowExpired =
		!prior || now - prior.windowStart >= bounds.windowSeconds;
	return {
		lastSentAt: now,
		dayCount: windowExpired ? 1 : prior.dayCount + 1,
		windowStart: windowExpired ? now : prior.windowStart
	};
}
