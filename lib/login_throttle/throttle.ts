import { adapter } from '../adapters/index.js';
import { ApplicationConfig } from '../configs/application.js';
import { emailScopedId } from '../helpers/email_scoped_id.js';
import epochTime from '../helpers/epoch_time.js';
import { LOGIN_RETENTION_SECONDS, windowFor } from './consts.js';
import type { LoginThrottlePayload } from './types.js';

/*
 * The password sign-in door's brute-force throttle: failed attempts counted per bucket-and-address
 * pair, the door shut for a growing window each time the count is exhausted.
 *
 * WHY THIS EXISTS SEPARATELY FROM lib/plugins/rateLimit.ts. That limiter counts requests per calling
 * origin, in memory, per instance — a resource protection whose effective allowance multiplies by the
 * number of machines and resets on restart. It cannot bound guesses against one identity, which is the
 * property this feature has to hold absolutely, so this one is persisted through the adapter and keyed
 * on the identity rather than on the caller.
 *
 * WHY THIS IS A NEAR-COPY OF lib/totp/verify.ts's failure window, and deliberately so: that is the
 * same throttle for the adjacent secret, and it settled every question this one faces — check before
 * verifying, write only on failure, destroy on success, one message for every failure. The one place
 * the two diverge is ownership: TotpAttempt is account-owned and carries `accountId`, while this area
 * must hold counters for addresses that resolve to no account at all (FR-002), so it is addressed and
 * unowned. That is why they cannot be one area.
 *
 * THE TWO HORIZONS, which are the easiest thing here to get wrong. `windowStart + windowFor(step)` is
 * when the *door* reopens; `exp` is when the *record* dies, 24 hours after the most recent failure.
 * The second must outlive the first: a record reaped when the door reopens restores step 0, so an
 * attacker who simply waits out each lockout keeps the shortest window for ever and the escalation
 * never happens. lib/configs/configuration.ts enforces the ordering at boot.
 *
 * NOTHING HERE FAILS OPEN. No call catches a storage error. The read sits one line ahead of the
 * account lookup, which reaches the same datastore, so a datastore that fails this would have failed
 * that a moment later: propagating costs no information and lets the error store record a real fault,
 * where catching would answer "invalid username or password" to a user whose sign-in was never
 * actually refused for that reason.
 */

function counters() {
	return adapter('LoginThrottle');
}

/* Addressed, never scanned for — the account cascade destroys it by computed id. */
export function throttleKey(bucketId: string, email: string): string {
	return emailScopedId(bucketId, email);
}

interface Bounds {
	readonly cap: number;
	readonly window: number;
	readonly ceiling: number;
}

/*
 * Read at call time rather than captured at module scope, the way lib/plugins/rateLimit.ts reads its
 * own: these are settings, and a value captured at import would ignore whatever a restart or a spec
 * put there.
 *
 * `secondFactorRequired` collapses the ceiling to the first window — the FR-025 rule. It arrives as an
 * argument rather than being looked up here, so this module reads no bucket and the rule stays visible
 * at the door where the same setting is already resolved for the second-factor redirect. Stated as a
 * property of the bucket's policy and never as a test on the bucket's id: the admin bucket needs the
 * short ceiling because it has no self-service password reset to escape a long one with, and writing
 * that as `bucketId === ADMIN_BUCKET_ID` would both hide the reason and freeze it.
 */
function boundsFor(secondFactorRequired: boolean): Bounds {
	const window = ApplicationConfig['loginThrottle.windowSeconds'] as number;
	const ceiling = ApplicationConfig[
		'loginThrottle.windowCeilingSeconds'
	] as number;
	return {
		cap: ApplicationConfig['loginThrottle.failureCap'] as number,
		window,
		ceiling: secondFactorRequired ? window : ceiling
	};
}

/*
 * The stored counter, or undefined when there is effectively none.
 *
 * Expiry is compared here rather than left to the adapter, which is the departure
 * lib/password_reset/challenge.ts makes for the opposite direction of the same reason: MongoDB's TTL
 * monitor deletes lazily — roughly once a minute, worse under load — so a counter whose retention has
 * passed would keep an address escalated for a while after it should have gone back to a clean slate.
 */
async function held(key: string): Promise<LoginThrottlePayload | undefined> {
	/*
	 * The adapter's payload type is the schema's, but the record is written straight through `upsert`
	 * with no model class to validate it, so the read is narrowed the way lib/totp/verify.ts narrows
	 * TotpAttempt: the type system cannot know that what came back matches what was written.
	 */
	const record = (await counters().find(key)) as
		LoginThrottlePayload | undefined;
	if (!record) return undefined;
	return record.exp <= epochTime() ? undefined : record;
}

/* Whether this address's current window is still shutting the door. */
function shut(record: LoginThrottlePayload, now: number, bounds: Bounds) {
	return (
		record.failures >= bounds.cap &&
		now - record.windowStart <
			windowFor(record.step, bounds.window, bounds.ceiling)
	);
}

/*
 * Whether the password door is currently closed for this address.
 *
 * Called before the account lookup and before any password verification, so a refused attempt costs
 * neither — which is what makes a flood against one address stop being a CPU cost as well as stopping
 * being a guessing opportunity.
 */
export async function isThrottled(
	bucketId: string,
	email: string,
	secondFactorRequired: boolean
): Promise<boolean> {
	const record = await held(throttleKey(bucketId, email));
	if (!record) return false;
	return shut(record, epochTime(), boundsFor(secondFactorRequired));
}

/*
 * One more failure for this address.
 *
 * Written for any address submitted to an open door, including one that resolves to no account: a
 * counter that existed only for real accounts would make the throttle's behaviour — and any future
 * divergence in the refusal — an account-existence oracle, and would let an attacker probe existence
 * by watching for it (FR-002).
 *
 * A read-modify-write, with no atomic increment because `ModelAdapter` has none and adding one is a
 * change to the storage interface. Concurrent attempts inside a single round-trip can therefore let
 * one extra verification through; lib/totp/verify.ts accepts the same race for the same shape, and the
 * per-origin limiter's `strict` allowance bounds how many an attacker can land.
 */
export async function recordFailure(
	bucketId: string,
	email: string
): Promise<void> {
	const key = throttleKey(bucketId, email);
	const now = epochTime();
	const prior = await held(key);
	/*
	 * The ceiling does not matter for the write: it only decides how long a window lasts, and what is
	 * being decided here is whether the current one is over. Passing the configured ceiling keeps the
	 * step advancing on the same schedule for every bucket, so a bucket that later turns its second
	 * factor off does not find its counters mysteriously behind.
	 */
	const bounds = boundsFor(false);

	const next = (() => {
		if (!prior) {
			return { failures: 1, windowStart: now, step: 0 };
		}
		const windowOpen =
			now - prior.windowStart <
			windowFor(prior.step, bounds.window, bounds.ceiling);
		if (windowOpen) {
			/*
			 * Already at the cap: the door is shut, so this attempt is refused without extending anything.
			 * `failures` still climbs — it costs nothing and says how hard the address is being worked —
			 * but `windowStart` and `step` stay put, which is what stops an attacker who keeps knocking
			 * from holding the door shut indefinitely by knocking.
			 */
			return {
				failures: prior.failures + 1,
				windowStart: prior.windowStart,
				step: prior.step
			};
		}
		/*
		 * The window has elapsed. If it was exhausted, this failure opens the next, longer one; if it was
		 * not, the address simply gets a fresh window at the same step.
		 */
		const exhausted = prior.failures >= bounds.cap;
		return {
			failures: 1,
			windowStart: now,
			step: exhausted ? prior.step + 1 : prior.step
		};
	})();

	await counters().upsert(
		key,
		{ ...next, exp: now + LOGIN_RETENTION_SECONDS },
		LOGIN_RETENTION_SECONDS
	);
}

/*
 * A clean slate. Two callers, and both hold a proof an attacker guessing passwords does not: a
 * password that verified, and a password reset that was *completed* — consuming a single-use secret
 * delivered to the address on file. Requesting a reset proves nothing and must never reach here.
 */
export async function clearFailures(
	bucketId: string,
	email: string
): Promise<void> {
	await counters().destroy(throttleKey(bucketId, email));
}
