/*
 * The arithmetic behind "has this origin had its share of requests this window" — the whole decision
 * the per-origin limiter makes, with none of the machinery that makes it.
 *
 * Separate from lib/helpers/rate_window.ts, which answers a different question for the per-identity
 * flows: how often one address may be made to *receive a security email*, with a cooldown and a daily
 * cap over a rolling window. This one counts requests against a fixed window and knows nothing about
 * identity. Sharing an implementation would mean one function with two sets of bounds and two refusal
 * vocabularies, which is how a security rule acquires a branch nobody re-reads.
 *
 * Pure by construction, and for the same stated reason its sibling gives: no clock, no adapter, no
 * constants of its own. `now` is passed in so the caller reads the clock once per request and a test
 * needs no fake one — which is what lets window expiry be proven with a synthetic clock instead of a
 * sleeping test.
 *
 * Called on every request ahead of routing, so it must be total: a throw here is a 500 on an endpoint
 * that was working.
 */

export interface RateBounds {
	/* Requests one origin may make inside a window. */
	readonly max: number;
	/* Length of the window, in seconds. */
	readonly windowSeconds: number;
}

/* One origin's tally within one route class. Nothing else is remembered about an origin. */
export interface OriginCounter {
	readonly count: number;
	/* Epoch seconds at which the current window opened. */
	readonly windowStart: number;
}

export interface RateDecision {
	readonly refused: boolean;
	/* Seconds to wait before retrying; 0 when the request was not refused. */
	readonly retryAfterSeconds: number;
	/* The counter state to write back. Always present, refused or not. */
	readonly next: OriginCounter;
}

/*
 * Whether this request is refused, and the counter that should replace the one passed in.
 *
 * A lapsed window is reset here rather than swept by a timer: the only moment the answer matters is
 * the moment it is asked for, so an expired entry costs nothing until it is read, and the store needs
 * no background work to keep it honest.
 */
export function decide(
	prior: OriginCounter | undefined,
	now: number,
	bounds: RateBounds
): RateDecision {
	const windowLapsed =
		prior === undefined || now - prior.windowStart >= bounds.windowSeconds;

	if (windowLapsed) {
		return {
			refused: false,
			retryAfterSeconds: 0,
			next: { count: 1, windowStart: now }
		};
	}

	if (prior.count >= bounds.max) {
		return {
			refused: true,
			/*
			 * Rounded up, and floored at one. A delay shorter than the time actually remaining sends a
			 * client that honours it straight into a second refusal, and a zero tells it to retry into a
			 * refusal still in force — so the two ways of being wrong here are the same way.
			 */
			retryAfterSeconds: Math.max(
				1,
				Math.ceil(prior.windowStart + bounds.windowSeconds - now)
			),
			/*
			 * Carried over unchanged. Charging a refused request would let a client that ignores
			 * Retry-After extend its own penalty with every retry — a permanent ban arrived at by
			 * accident, with no operator action behind it and no way for the client to escape.
			 */
			next: prior
		};
	}

	return {
		refused: false,
		retryAfterSeconds: 0,
		next: { count: prior.count + 1, windowStart: prior.windowStart }
	};
}
