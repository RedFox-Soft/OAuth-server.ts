import QuickLRU from 'quick-lru';

import { ApplicationConfig } from '../configs/application.js';
import {
	decide,
	type OriginCounter,
	type RateBounds
} from './rate_limit_window.js';

/*
 * The per-origin charge for a request whose credential failed, on the surfaces that are not counted by the
 * per-origin limiter's strict class on every request: SCIM (exempt, counted per connection) and global token
 * revocation (ordinary). One counter for both, so a guesser alternating between them is charged once, at the
 * token endpoint's strict bounds — it gets no more room here than there.
 *
 * Each surface throws in its own error shape, so the refusal is a callback rather than an error class.
 */

const MAX_TRACKED = 10_000;

const byOrigin = new QuickLRU<string, OriginCounter>({ maxSize: MAX_TRACKED });

/* The clock, injectable for the tests only — a spec that waited out a window would be a spec nobody runs. */
let clock: () => number = () => Math.floor(Date.now() / 1000);

export function setUnauthenticatedChargeClock(
	next: (() => number) | null
): void {
	clock = next ?? (() => Math.floor(Date.now() / 1000));
}

export function resetUnauthenticatedCharge(): void {
	byOrigin.clear();
}

function strictBounds(): RateBounds {
	return {
		max: ApplicationConfig['rateLimit.strict.max'],
		windowSeconds: ApplicationConfig['rateLimit.strict.windowSeconds']
	};
}

/*
 * Skipped while the per-origin limiter is switched off, so one switch still turns all request limiting off
 * for an operator diagnosing a false refusal.
 */
export function chargeFailedCredential(
	origin: string,
	refuse: (retryAfterSeconds: number) => Error
): void {
	if (!ApplicationConfig['rateLimit.enabled']) return;
	const decision = decide(byOrigin.get(origin), clock(), strictBounds());
	byOrigin.set(origin, decision.next);
	if (decision.refused) throw refuse(decision.retryAfterSeconds);
}
