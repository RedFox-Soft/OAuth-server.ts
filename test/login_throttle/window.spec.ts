import { describe, it, expect, beforeEach } from 'bun:test';

import { adapter } from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import {
	LOGIN_RETENTION_SECONDS,
	windowFor
} from 'lib/login_throttle/consts.ts';
import {
	clearFailures,
	isThrottled,
	recordFailure,
	throttleKey
} from 'lib/login_throttle/throttle.ts';
import type { LoginThrottlePayload } from 'lib/login_throttle/types.ts';
import { TestAdapter } from 'test/models.js';

/*
 * The throttle engine at its own seam, before any HTTP is involved. Its eight contract properties are
 * in specs/032-login-brute-force/contracts/login-throttle.md § 3; the two that earn a spec of their
 * own rather than an end-to-end case are the ones a flat implementation would otherwise pass:
 * `step` advancing when a window has elapsed, and the record outliving the window that shut the door.
 *
 * A per-bucket door is exercised through the HTTP layer in signin.spec.ts. This file is deliberately
 * storage-only: no interaction, no client, no bucket.
 */

const CAP = ApplicationConfig['loginThrottle.failureCap'] as number;
const WINDOW = ApplicationConfig['loginThrottle.windowSeconds'] as number;
const CEILING = ApplicationConfig[
	'loginThrottle.windowCeilingSeconds'
] as number;

const BUCKET = 'window-spec';
let seq = 0;
/* A fresh address per case: the store is module state and nothing clears it between files. */
const address = () => `case-${(seq += 1)}@x.io`;

/* The memory adapter stores the payload flat under its prefixed key, so this is the record itself. */
function record(email: string): LoginThrottlePayload | undefined {
	return TestAdapter.for('LoginThrottle').syncFind(
		throttleKey(BUCKET, email)
	) as LoginThrottlePayload | undefined;
}

/* Exhaust one window's worth of attempts. */
async function exhaust(email: string): Promise<void> {
	for (let i = 0; i < CAP; i += 1) {
		await recordFailure(BUCKET, email);
	}
}

/*
 * Reopen the door without waiting: move the window's start back far enough that the current window has
 * elapsed, leaving `step` and `failures` exactly where they were. This is the state a real address is
 * in the moment its lockout ends — and the state that tells escalation from a flat window.
 */
function ageWindow(email: string, by = CEILING + 1): void {
	const held = record(email);
	if (!held) throw new Error('expected a counter to age');
	TestAdapter.for('LoginThrottle').syncUpdate(throttleKey(BUCKET, email), {
		windowStart: held.windowStart - by
	});
}

describe('login throttle: the curve', () => {
	it('doubles from the first window up to the ceiling and stops there', () => {
		expect(windowFor(0, 900, 3600)).toBe(900);
		expect(windowFor(1, 900, 3600)).toBe(1800);
		expect(windowFor(2, 900, 3600)).toBe(3600);
		expect(windowFor(3, 900, 3600)).toBe(3600);
		expect(windowFor(99, 900, 3600)).toBe(3600);
	});

	it('stays flat when the ceiling is the first window', () => {
		// What a bucket requiring a second factor gets: the caller resolves the ceiling, not this function.
		expect(windowFor(0, 900, 900)).toBe(900);
		expect(windowFor(5, 900, 900)).toBe(900);
	});

	it('never returns a nonsense window for a nonsense step', () => {
		expect(windowFor(-1, 900, 3600)).toBe(900);
		expect(Number.isFinite(windowFor(1e9, 900, 3600))).toBe(true);
	});

	it('keeps a counter alive longer than the longest window it can impose', () => {
		// The property the whole escalation rests on. If this inverts, a reaped counter is a reset counter.
		expect(LOGIN_RETENTION_SECONDS).toBeGreaterThan(CEILING);
	});
});

describe('login throttle: counting', () => {
	beforeEach(() => {
		TestAdapter.clear();
	});

	it('is not throttled with no record at all', async () => {
		expect(await isThrottled(BUCKET, address(), false)).toBe(false);
	});

	it('opens a window at step zero on the first failure', async () => {
		const email = address();
		const before = epochTime();
		await recordFailure(BUCKET, email);

		const held = record(email);
		expect(held).toBeDefined();
		expect(held?.failures).toBe(1);
		expect(held?.step).toBe(0);
		expect(held?.windowStart).toBeGreaterThanOrEqual(before);
		expect(held?.exp).toBeGreaterThanOrEqual(before + LOGIN_RETENTION_SECONDS);
	});

	it('is not throttled below the cap', async () => {
		const email = address();
		for (let i = 0; i < CAP - 1; i += 1) {
			await recordFailure(BUCKET, email);
		}
		expect(await isThrottled(BUCKET, email, false)).toBe(false);
	});

	it('is throttled at the cap', async () => {
		const email = address();
		await exhaust(email);
		expect(await isThrottled(BUCKET, email, false)).toBe(true);
	});

	it('counts up inside an open window without moving the window or the step', async () => {
		const email = address();
		await recordFailure(BUCKET, email);
		const first = record(email);
		await recordFailure(BUCKET, email);
		const second = record(email);

		expect(second?.failures).toBe(2);
		expect(second?.windowStart).toBe(first?.windowStart);
		expect(second?.step).toBe(0);
	});

	it('holds an address that keeps knocking without extending its current window', async () => {
		const email = address();
		await exhaust(email);
		const shut = record(email);

		await recordFailure(BUCKET, email);

		const after = record(email);
		expect(after?.windowStart).toBe(shut?.windowStart);
		expect(after?.step).toBe(shut?.step);
		expect(await isThrottled(BUCKET, email, false)).toBe(true);
	});
});

describe('login throttle: escalation', () => {
	beforeEach(() => {
		TestAdapter.clear();
	});

	it('reopens the door when the window elapses, and keeps the record', async () => {
		const email = address();
		await exhaust(email);
		ageWindow(email);

		expect(await isThrottled(BUCKET, email, false)).toBe(false);
		// The record survives its own window. Reap it here and every attacker who waits restarts at step 0.
		expect(record(email)).toBeDefined();
	});

	it('advances the step on the next exhaustion rather than resetting to the first window', async () => {
		const email = address();
		await exhaust(email);
		ageWindow(email);
		await exhaust(email);

		const held = record(email);
		expect(held?.step).toBe(1);
		expect(await isThrottled(BUCKET, email, false)).toBe(true);
	});

	it('shuts the door for longer each time, up to the ceiling and no further', async () => {
		const email = address();
		const seen: number[] = [];
		for (let round = 0; round < 4; round += 1) {
			await exhaust(email);
			const held = record(email);
			seen.push(windowFor(held?.step ?? 0, WINDOW, CEILING));
			ageWindow(email);
		}

		expect(seen[0]).toBe(WINDOW);
		expect(seen[1]).toBeGreaterThan(seen[0] as number);
		expect(seen[3]).toBe(CEILING);
		expect(seen[3]).toBe(seen[2]);
	});

	it('holds the curve flat for a bucket that requires a second factor', async () => {
		const email = address();
		await exhaust(email);
		ageWindow(email, WINDOW + 1);

		/*
		 * The step has advanced, but a second-factor bucket's ceiling is the first window — so a lockout
		 * that would still be running for a password-only bucket has already ended here.
		 */
		await exhaust(email);
		ageWindow(email, WINDOW + 1);
		expect(await isThrottled(BUCKET, email, true)).toBe(false);
		expect((record(email)?.step ?? 0) > 0).toBe(true);
	});

	it('starts again at the first window once the retention period has passed', async () => {
		const email = address();
		await exhaust(email);
		ageWindow(email);
		await exhaust(email);
		expect(record(email)?.step).toBe(1);

		// What the datastore's TTL leaves behind, and what a lazy monitor has not got to yet.
		TestAdapter.for('LoginThrottle').syncUpdate(throttleKey(BUCKET, email), {
			exp: epochTime() - 1
		});

		expect(await isThrottled(BUCKET, email, false)).toBe(false);
		await recordFailure(BUCKET, email);
		expect(record(email)?.step).toBe(0);
		expect(record(email)?.failures).toBe(1);
	});

	it('treats an expired record as absent even while it is still stored', async () => {
		const email = address();
		await exhaust(email);
		expect(await isThrottled(BUCKET, email, false)).toBe(true);

		TestAdapter.for('LoginThrottle').syncUpdate(throttleKey(BUCKET, email), {
			exp: epochTime() - 1
		});

		expect(await isThrottled(BUCKET, email, false)).toBe(false);
		expect(record(email)).toBeDefined();
	});
});

describe('login throttle: clearing and keying', () => {
	beforeEach(() => {
		TestAdapter.clear();
	});

	it('clears a standing lockout outright', async () => {
		const email = address();
		await exhaust(email);
		await clearFailures(BUCKET, email);

		expect(record(email)).toBeUndefined();
		expect(await isThrottled(BUCKET, email, false)).toBe(false);
	});

	it('clears an address that never failed without complaining', async () => {
		// Called from the password-reset flow, which has no idea whether the address ever failed.
		await expect(clearFailures(BUCKET, address())).resolves.toBeUndefined();
	});

	it('gives one counter to every casing of one address', async () => {
		// A 16-letter address has 2^16 casings that all resolve to the same account. Each one must not
		// buy a fresh allowance — see FR-024.
		expect(throttleKey(BUCKET, 'Alice@X.io')).toBe(
			throttleKey(BUCKET, 'alice@x.io')
		);

		const spellings = ['Alice@x.io', 'aLICE@x.io', 'ALICE@X.IO', 'alice@x.IO'];
		for (let i = 0; i < CAP; i += 1) {
			await recordFailure(BUCKET, spellings[i % spellings.length] as string);
		}

		expect(await isThrottled(BUCKET, 'alice@x.io', false)).toBe(true);
	});

	it('keeps the same address in two buckets apart', async () => {
		const email = address();
		await exhaust(email);

		expect(await isThrottled('another-bucket', email, false)).toBe(false);
	});

	it('does not fail open when the counter cannot be read', async () => {
		const email = address();
		const store = adapter('LoginThrottle');
		const find = store.find;
		store.find = () => Promise.reject(new Error('datastore is gone'));

		try {
			await expect(isThrottled(BUCKET, email, false)).rejects.toThrow(
				'datastore is gone'
			);
		} finally {
			store.find = find;
		}
	});
});
