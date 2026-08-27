import { adapter, getUserStore } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { decodeBase32 } from './base32.js';
import { verifyAt } from './code.js';
import { ACCOUNT_FAILURE_CAP, ACCOUNT_WINDOW_SECONDS } from './consts.js';
import type { TotpAttemptPayload } from './types.js';

/*
 * Verification against a standing enrolment, with both things that make a six-digit secret survivable:
 * the replay guard and the per-account failure window.
 *
 * The window arithmetic is written here rather than taken from lib/helpers/rate_window.ts, and that is
 * a decision rather than an oversight. That helper exists because "how often may one address be made to
 * receive a security email" is a security rule with two callers, and its own comment is explicit that
 * only the arithmetic is shared while the bounds and storage stay with each flow. What is shared with
 * this flow is narrower still — a rolling window and a cap, three lines — while its record shape
 * (`lastSentAt`, `dayCount`) and its refusal vocabulary (`cooldown` | `daily`) describe sends. Counting
 * failed codes in fields named after sends, with a cooldown pinned to zero to disable a concept this
 * flow does not have, would make both callers harder to read in exchange for no shared rule.
 */

function attempts() {
	return adapter('TotpAttempt');
}

/* Addressed, never scanned for — the account cascade destroys it by computed id. */
export function attemptKey(bucketId: string, accountId: string): string {
	return `${bucketId}:${accountId}`;
}

export type Outcome =
	| { ok: true }
	| { ok: false; reason: 'invalid' | 'throttled' | 'not_enrolled' };

/*
 * `throttled` and `invalid` are separated for the caller's benefit only — one of them is worth a log
 * line and the other is not. Both reach the person as the same words, because a distinct "too many
 * attempts" message tells an attacker their guessing is registering against a real account.
 */
export async function verifyForAccount(
	bucketId: string,
	accountId: string,
	code: string
): Promise<Outcome> {
	const store = getUserStore(bucketId);
	const user = await store.find(accountId);
	if (!user?.totp) {
		return { ok: false, reason: 'not_enrolled' };
	}

	const now = epochTime();
	const key = attemptKey(bucketId, accountId);
	const prior = (await attempts().find(key)) as TotpAttemptPayload | undefined;
	const windowActive =
		prior !== undefined && now - prior.windowStart < ACCOUNT_WINDOW_SECONDS;

	// Checked before verifying, so a locked-out account refuses even a correct code — the same shape
	// lib/verification/challenge.ts uses once its attempt cap is reached.
	if (windowActive && prior.failures >= ACCOUNT_FAILURE_CAP) {
		return { ok: false, reason: 'throttled' };
	}

	const step = verifyAt(decodeBase32(user.totp.secret), code, now, {
		after: user.totp.lastStep
	});

	if (step === null) {
		const failures = windowActive ? prior.failures + 1 : 1;
		const windowStart = windowActive ? prior.windowStart : now;
		// The record dies with the window rather than outliving it, so a lockout cannot become permanent.
		const ttl = Math.max(1, windowStart + ACCOUNT_WINDOW_SECONDS - now);
		await attempts().upsert(
			key,
			{ accountId, failures, windowStart, exp: now + ttl },
			ttl
		);
		return { ok: false, reason: 'invalid' };
	}

	/*
	 * Advancing `lastStep` is what makes FR-018 true, and it is the easiest part of this to lose: with
	 * verification implemented as a pure predicate, a code observed in flight stays usable for the whole
	 * remaining drift band.
	 */
	await store.update(accountId, { totp: { ...user.totp, lastStep: step } });
	await attempts().destroy(key);
	return { ok: true };
}

/* A clean slate: on a completed sign-in, and when an operator clears the enrolment entirely. */
export async function clearAttempts(
	bucketId: string,
	accountId: string
): Promise<void> {
	await attempts().destroy(attemptKey(bucketId, accountId));
}
