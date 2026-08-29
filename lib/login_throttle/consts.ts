/*
 * The password sign-in door's failure-throttle arithmetic, and the one bound that is derived rather
 * than configured. The three tunable numbers live on ApplicationConfig
 * (`loginThrottle.failureCap`, `.windowSeconds`, `.windowCeilingSeconds`) because this is the one
 * per-identity throttle whose numbers trade security against locking real people out, and where the
 * right point genuinely differs by deployment — a consumer product and an internal tool have
 * different tolerances. A six-digit code's arithmetic does not vary that way, which is why
 * lib/totp/consts.ts and lib/verification/consts.ts are plain constants.
 *
 * THE ARITHMETIC, written down as lib/totp/consts.ts writes down ACCOUNT_FAILURE_CAP's, so it can be
 * re-checked when a number moves. With the defaults — 5 failures per step, windows of 900s doubling
 * to a 3600s ceiling — a single address is held to 5 guesses per hour once escalation tops out, about
 * 120 a day, against unlimited before this feature existed. That lands beside NIST SP 800-63B
 * §5.2.2's guidance of no more than 100 consecutive failed attempts per account. A *flat* 900s window
 * would permit 480 a day, and — the real problem — an attacker who simply waits out each window keeps
 * that allowance for ever, which is what the escalation exists to stop.
 *
 * Where the bucket requires a second factor the curve stays flat at the first step, because a guessed
 * password there does not complete a sign-in while the lockout it risks is the one nobody can undo:
 * the reserved admin bucket has no self-service password reset, so its operators cannot use the escape
 * hatch every other population has. That rule is applied in throttle.ts, from the bucket's setting
 * rather than from the bucket's identity.
 */

/*
 * How long a counter survives its most recent failure.
 *
 * Derived, not a setting, and it must EXCEED the current window or the escalation above cannot happen
 * at all: a record reaped when the door reopens restores step 0, so every attacker who waits restarts
 * at the shortest window. The config validator therefore caps `windowCeilingSeconds` at this value
 * (lib/configs/configuration.ts), which is what keeps "retention outlives the window" true without
 * asking an operator to maintain two numbers in the right order.
 *
 * Measuring from the last failure rather than from the first is what makes the escalation step decay
 * on its own after a quiet day, instead of needing a second horizon to expire it.
 */
export const LOGIN_RETENTION_SECONDS = 24 * 60 * 60;

/*
 * How long the door stays shut for an address that has exhausted `step` windows.
 *
 * Pure: no clock, no config, no adapter — the caller reads its bounds once per operation, which is
 * what lets a test check the curve without a fake clock. `ceilingSeconds` is what the caller has
 * already resolved for this bucket, so the second-factor rule is decided at the call site and is not
 * hidden in here.
 */
export function windowFor(
	step: number,
	windowSeconds: number,
	ceilingSeconds: number
): number {
	/*
	 * Doubling rather than a configured list of steps: a curve an operator can shape point by point is
	 * a curve that can be shaped into no protection, and every intermediate value an operator could
	 * want is between the first window and the ceiling they already set.
	 *
	 * The exponent is clamped before it is used. 2 ** step on an unbounded step is Infinity long before
	 * it is a bug anyone notices, and `Math.min` would hide it: the record's step is data, and data
	 * that reached an absurd value should not silently produce a plausible window.
	 */
	const doublings = Math.min(Math.max(step, 0), 32);
	return Math.min(windowSeconds * 2 ** doublings, ceilingSeconds);
}
