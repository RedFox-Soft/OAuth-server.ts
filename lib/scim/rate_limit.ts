import QuickLRU from 'quick-lru';

import { ApplicationConfig } from '../configs/application.js';
import {
	decide,
	type OriginCounter,
	type RateBounds
} from '../helpers/rate_limit_window.js';
import { ScimError } from './errors.js';

/*
 * SCIM's own limiters. The SCIM routes are exempt from the per-origin limiter (route_classification.ts),
 * because its ordinary class allows five requests a second per address while IPSIE AL SCIM §4.3 requires at
 * least 25 per tenant, and Entra and Okta send many tenants' traffic from a few addresses (specs/070 R9).
 *
 * So two counters live here instead:
 *   - per connection, once the credential is resolved — the tenant IPSIE means;
 *   - per origin, for requests whose credential failed, with the strict bounds, so a token-guesser gets
 *     no more room on this surface than on the token endpoint.
 *
 * The refusal is thrown from inside the SCIM plugin, after routing, so it renders in SCIM's error shape —
 * which the per-origin limiter's, thrown before routing, never could.
 */

const MAX_TRACKED = 10_000;

const byConnection = new QuickLRU<string, OriginCounter>({
	maxSize: MAX_TRACKED
});
const unauthenticatedByOrigin = new QuickLRU<string, OriginCounter>({
	maxSize: MAX_TRACKED
});

/* The clock, injectable for the tests only — a spec that waited out a window would be a spec nobody runs. */
let clock: () => number = () => Math.floor(Date.now() / 1000);

export function setScimRateLimitClock(next: (() => number) | null): void {
	clock = next ?? (() => Math.floor(Date.now() / 1000));
}

export function resetScimRateLimiter(): void {
	byConnection.clear();
	unauthenticatedByOrigin.clear();
}

/*
 * Bounds are read on every request, so a saved allowance applies to the next one; counters already running
 * keep their window, because replacing them would hand every connection a clean allowance on an edit.
 */
function connectionBounds(): RateBounds {
	return {
		max: ApplicationConfig['scim.rateLimit.max'] as number,
		windowSeconds: ApplicationConfig['scim.rateLimit.windowSeconds'] as number
	};
}

function strictBounds(): RateBounds {
	return {
		max: ApplicationConfig['rateLimit.strict.max'] as number,
		windowSeconds: ApplicationConfig['rateLimit.strict.windowSeconds'] as number
	};
}

function charge(
	store: QuickLRU<string, OriginCounter>,
	key: string,
	bounds: RateBounds
): void {
	const decision = decide(store.get(key), clock(), bounds);
	store.set(key, decision.next);
	if (decision.refused) {
		throw new ScimError(
			429,
			undefined,
			'too many requests; retry after the interval in Retry-After',
			{ 'Retry-After': String(decision.retryAfterSeconds) }
		);
	}
}

export function chargeConnection(connectionId: string): void {
	charge(byConnection, connectionId, connectionBounds());
}

/*
 * Charged only when authentication failed. Skipped while the per-origin limiter is switched off, so one
 * switch still turns all request limiting off for an operator diagnosing a false refusal.
 */
export function chargeUnauthenticated(origin: string): void {
	if (ApplicationConfig['rateLimit.enabled'] !== true) return;
	charge(unauthenticatedByOrigin, origin, strictBounds());
}
