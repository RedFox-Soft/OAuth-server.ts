import QuickLRU from 'quick-lru';

import { ApplicationConfig } from '../configs/application.js';
import { callerAddressOf } from '../helpers/caller_address.js';
import {
	decide,
	type OriginCounter,
	type RateBounds
} from '../helpers/rate_limit_window.js';
import { chargeFailedCredential } from '../helpers/unauthenticated_charge.js';

/*
 * The check's own limiter (specs/122 R3). The check is exempt from the per-origin limiter
 * (lib/consts/route_classification.ts), because every person behind one proxy reaches it from the proxy's one
 * address, and a per-address limit would turn a whole office away at once. So it is counted per app, which is
 * what one proxy's traffic is about, and a check naming no app this project holds is charged to the caller with
 * the strict bounds, as a failed credential is everywhere else.
 */

export class CheckRateLimited extends Error {
	constructor(readonly retryAfterSeconds: number) {
		super('too many checks for this app');
	}
}

/*
 * Generous on purpose: every asset of every page of the app is one check. Not a setting (research R4): the limit
 * protects the instance from one app's flood and is not something an operator tunes per deployment.
 */
const APP_BOUNDS: RateBounds = { max: 6000, windowSeconds: 60 };

const MAX_TRACKED = 10_000;

const byApp = new QuickLRU<string, OriginCounter>({ maxSize: MAX_TRACKED });

let bounds: RateBounds = APP_BOUNDS;

/* Tests only: a bound small enough to reach within one case. */
export function setCheckRateBoundsForTests(next: RateBounds | null): void {
	bounds = next ?? APP_BOUNDS;
}

export function resetCheckRateLimiter(): void {
	byApp.clear();
}

/* Skipped while request limiting is switched off, so one switch still turns all of it off. */
export function chargeApp(appId: string): void {
	if (!ApplicationConfig['rateLimit.enabled']) return;
	const decision = decide(
		byApp.get(appId),
		Math.floor(Date.now() / 1000),
		bounds
	);
	byApp.set(appId, decision.next);
	if (decision.refused) throw new CheckRateLimited(decision.retryAfterSeconds);
}

/*
 * Who is calling the check: the proxy, never the person it is asking about. A proxy sends the browser's address
 * in `X-Forwarded-For`, and where the operator's proxy is one the instance trusts that header would otherwise be
 * believed (lib/helpers/caller_address.ts), making the person's address the caller of an instance-wide limit or
 * record (FR-022). So here a caller resolved from that header is replaced by the connection it arrived on.
 */
export function checkCallerOf(request: Request): string {
	const caller = callerAddressOf(request);
	return caller.from === 'x-forwarded-for'
		? (caller.connection ?? caller.address)
		: caller.address;
}

export function chargeUnknown(request: Request): void {
	chargeFailedCredential(
		checkCallerOf(request),
		(retryAfterSeconds) => new CheckRateLimited(retryAfterSeconds)
	);
}
