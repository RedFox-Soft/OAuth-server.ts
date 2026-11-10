import { checkedAdapter, getUserStore } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { decodeBase32 } from './base32.js';
import { verifyAt } from './code.js';
import {
	ACCOUNT_FAILURE_CAP,
	ACCOUNT_WINDOW_SECONDS,
	DAILY_FAILURE_CAP,
	DAILY_WINDOW_SECONDS,
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
	| {
			ok: false;
			reason: 'invalid' | 'throttled' | 'not_enrolled';
			/* This wrong code used up the short window, the first time today: the person is to be told. */
			exhausted?: true;
	  };

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
	/*
	 * Two windows, each counted before the code is checked: ten wrong codes in fifteen minutes, and thirty in a day
	 * (specs/126 research R9). The short one alone let a script that knows the password guess 960 codes a day.
	 */
	const attempt = await countAttempt(
		key,
		accountId,
		now,
		ACCOUNT_WINDOW_SECONDS,
		ACCOUNT_FAILURE_CAP
	);
	if (attempt > ACCOUNT_FAILURE_CAP) {
		return { ok: false, reason: 'throttled' };
	}
	const today = await countAttempt(
		dayKey(key),
		accountId,
		now,
		DAILY_WINDOW_SECONDS,
		DAILY_FAILURE_CAP
	);
	if (today > DAILY_FAILURE_CAP) {
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
		/*
		 * The wrong code that uses up the short window: someone holding the password is guessing, which is the best
		 * sign of a stolen password the server has. The caller tells the person, at most once a day.
		 */
		if (attempt === ACCOUNT_FAILURE_CAP && (await firstWarningToday(key))) {
			return { ok: false, reason: 'invalid', exhausted: true };
		}
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

/*
 * A clean slate, both windows: when an operator clears the enrolment, and when a password reset by its mailed link
 * proves the owner is back (specs/126 FR-024). A completed sign-in clears only the short window.
 */
export async function clearAttempts(
	bucketId: string,
	accountId: string
): Promise<void> {
	const key = attemptKey(bucketId, accountId);
	await attempts().destroy(key);
	await attempts().destroy(dayKey(key));
}

function dayKey(key: string): string {
	return `${key}:day`;
}

/*
 * One more attempt in a window, answering its number, or more than `cap` when the window is already used up. Counted
 * in one atomic write that answers this attempt's own number: counting after the check was a read-modify-write, and a
 * burst of parallel guesses all read the same count and together advanced it by one. Opening a window is an
 * insert-if-absent for the same reason, and the record dies with its window, so a lockout cannot become permanent.
 */
async function countAttempt(
	key: string,
	accountId: string,
	now: number,
	windowSeconds: number,
	cap: number
): Promise<number> {
	const prior = await attempts().find(key);
	const active = prior !== undefined && now - prior.windowStart < windowSeconds;
	// Checked first, so a locked-out account refuses even a correct code, as lib/verification/challenge.ts does.
	if (active && prior.failures >= cap) return cap + 1;
	if (!active) {
		await attempts().create(
			key,
			{ accountId, failures: 0, windowStart: now, exp: now + windowSeconds },
			windowSeconds
		);
	}
	// Absent only when a concurrent success cleared the record in between: this attempt starts a fresh slate.
	return (await attempts().increment(key, 'failures')) ?? 1;
}

/* Marks today's warning as given, answering whether this is the first. A race costs at most a second mail. */
async function firstWarningToday(key: string): Promise<boolean> {
	const day = await attempts().find(dayKey(key));
	if (!day || day.notifiedAt !== undefined) return false;
	const remaining = day.exp - epochTime();
	if (remaining <= 0) return false;
	await attempts().upsert(
		dayKey(key),
		{ ...day, notifiedAt: epochTime() },
		remaining
	);
	return true;
}
