import { checkedAdapter, getUserStore } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { decodeBase32 } from './base32.js';
import { verifyAt } from './code.js';
import {
	ACCOUNT_FAILURE_CAP,
	ACCOUNT_WINDOW_SECONDS,
	SPENT_STEP_TTL_SECONDS
} from './consts.js';
import { TotpAttemptPayload, TotpSpentStepPayload } from './types.js';

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
	return checkedAdapter('TotpAttempt', TotpAttemptPayload);
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
	const prior = await attempts().find(key);
	const windowActive =
		prior !== undefined && now - prior.windowStart < ACCOUNT_WINDOW_SECONDS;

	// Checked before verifying, so a locked-out account refuses even a correct code — the same shape
	// lib/verification/challenge.ts uses once its attempt cap is reached.
	if (windowActive && prior.failures >= ACCOUNT_FAILURE_CAP) {
		return { ok: false, reason: 'throttled' };
	}

	/*
	 * The attempt is counted before the code is checked, in one atomic write that answers this
	 * attempt's own number. Counting a failure after checking was a read-modify-write, and a burst of
	 * parallel guesses all read the same count and together advanced it by one. A right code is counted
	 * too, harmlessly: success destroys the record.
	 *
	 * Opening a window is an insert-if-absent for the same reason, and the record dies with its window
	 * rather than outliving it — so a lockout cannot become permanent, and an expired record is one
	 * `create` treats as absent.
	 */
	if (!windowActive) {
		await attempts().create(
			key,
			{
				accountId,
				failures: 0,
				windowStart: now,
				exp: now + ACCOUNT_WINDOW_SECONDS
			},
			ACCOUNT_WINDOW_SECONDS
		);
	}
	// Absent only when a concurrent success cleared the record in between, which makes this attempt the
	// first of a fresh slate.
	const attempt = (await attempts().increment(key, 'failures')) ?? 1;
	if (attempt > ACCOUNT_FAILURE_CAP) {
		return { ok: false, reason: 'throttled' };
	}

	/*
	 * A secret the keyring cannot open (specs/116) is absent here, and the second factor is then refused like a
	 * wrong code, never skipped; an administrator resets the authenticator so the person enrols again.
	 */
	if (typeof user.totp.secret !== 'string') {
		return { ok: false, reason: 'invalid' };
	}
	const step = verifyAt(decodeBase32(user.totp.secret), code, now, {
		after: user.totp.lastStep
	});

	if (step === null) {
		return { ok: false, reason: 'invalid' };
	}

	/*
	 * Spending the step is what makes FR-018 true, and it is the easiest part of this to lose: with verification
	 * implemented as a pure predicate, a code observed in flight stays usable for the whole remaining drift band.
	 *
	 * It is one insert-if-absent, so of several verifications of the same code racing here exactly one is let
	 * through. Advancing `lastStep` on the person did not do that: two verifications both passed the check before
	 * either wrote, a slower one could write an older step back, and because the write carried the whole `totp`
	 * object it could restore a factor an administrator had just cleared or the person had just replaced. The
	 * enrolment is part of the key, so a step spent under an old secret never refuses a new one.
	 */
	const spent = await spentSteps().create(
		spentKey(bucketId, accountId, user.totp.enrolledAt, step),
		{ accountId, exp: now + SPENT_STEP_TTL_SECONDS },
		SPENT_STEP_TTL_SECONDS
	);
	if (!spent) {
		return { ok: false, reason: 'invalid' };
	}

	/*
	 * Read again rather than trusted from the read above: the factor this code proved may have been cleared or
	 * replaced, or the account deleted, while it was being checked, and success then would sign a person in on a
	 * factor that is no longer theirs, or as an account that no longer exists. Nothing is written to the person, so
	 * nothing can bring an old factor back.
	 *
	 * `not_enrolled` rather than a reason of its own, because it is true and because the caller already routes it
	 * somewhere terminating: the enrolment GET looks the account up, finds no factor or no account, and sends them
	 * on or back to the login door.
	 */
	const current = await store.find(accountId);
	if (!sameEnrolment(current?.totp?.enrolledAt, user.totp.enrolledAt)) {
		return { ok: false, reason: 'not_enrolled' };
	}

	await attempts().destroy(key);
	return { ok: true };
}

function spentSteps() {
	return checkedAdapter('TotpSpentStep', TotpSpentStepPayload);
}

function enrolmentMark(enrolledAt: Date | string | undefined): number {
	return enrolledAt === undefined ? Number.NaN : new Date(enrolledAt).getTime();
}

function sameEnrolment(
	a: Date | string | undefined,
	b: Date | string | undefined
): boolean {
	return enrolmentMark(a) === enrolmentMark(b);
}

/* Addressed, never scanned for; it expires on its own and dies with the account. */
function spentKey(
	bucketId: string,
	accountId: string,
	enrolledAt: Date | string,
	step: number
): string {
	return `${bucketId}:${accountId}:${enrolmentMark(enrolledAt)}:${step}`;
}

/* A clean slate: on a completed sign-in, and when an operator clears the enrolment entirely. */
export async function clearAttempts(
	bucketId: string,
	accountId: string
): Promise<void> {
	await attempts().destroy(attemptKey(bucketId, accountId));
}
