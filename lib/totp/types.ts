import { Type as t, type Static } from '@sinclair/typebox';

// TypeBox schemas rather than plain interfaces, for the reason lib/verification/types.ts states in
// full: the storage-ownership drift guard reads an area's payload fields at runtime, and an
// interface erases. Both payloads name `accountId`, which is one of the fields a deleted account's
// cascade sweeps — so the inventory must declare both areas account-owned, and the guard's reverse
// check is what makes that mandatory rather than optional.
//
// The records are written straight through `adapter('TotpEnrollment')` / `adapter('TotpAttempt')`
// and never through a model class, so nothing validates them against these schemas — they exist to
// be introspected, not to gate a write.

/*
 * A secret that has been offered to a person but not yet proved. Keyed by the **interaction uid**,
 * which is what makes it reachable only from inside the interaction that started it: there is no
 * enrolment handle in a form field to leak or guess, and a refresh or a wrong code re-reads the same
 * record and therefore re-offers the same secret. A fresh secret on every wrong code would mean a
 * person who mistyped a digit has to delete and re-add the entry in their authenticator app.
 *
 * `exp` mirrors the adapter's expiry (epoch seconds) and is asserted by the test adapter.
 */
export const TotpEnrollmentPayload = t.Object({
	accountId: t.String(),
	bucketId: t.String(),
	// Base32. Never reaches `user.totp` without a correct code, and never reaches a log or an audit entry.
	secret: t.String(),
	exp: t.Number(),
	/*
	 * On the person's own page (specs/126): the factor a replacement is replacing (`enrolledAt`, epoch ms), so it writes
	 * only while that one is still in place, and the wrong codes typed against this offer. At sign-in the interaction
	 * counts them instead.
	 */
	replacing: t.Optional(t.Number()),
	attempts: t.Optional(t.Number())
});

export type TotpEnrollmentPayload = Static<typeof TotpEnrollmentPayload>;

/*
 * The per-account failure window, keyed by `${bucketId}:${accountId}`.
 *
 * Separate from the per-interaction counter on the Interaction record because the two limit
 * different things: a counter that lived only on the interaction is defeated by starting a new one,
 * which costs an attacker a single request.
 *
 * Written only on a failure, so an account that never fails leaves nothing behind.
 */
export const TotpAttemptPayload = t.Object({
	accountId: t.String(),
	failures: t.Number(),
	windowStart: t.Number(),
	exp: t.Number(),
	/*
	 * On the day record only (`${bucketId}:${accountId}:day`, specs/126 research R9): when the person was mailed that
	 * someone with their password could not give the code, so that mail goes at most once per day window.
	 */
	notifiedAt: t.Optional(t.Number())
});

export type TotpAttemptPayload = Static<typeof TotpAttemptPayload>;

/*
 * One accepted step of one enrolment, keyed by `${bucketId}:${accountId}:${enrolledAt ms}:${step}`. Its existence is
 * the replay guard: the insert-if-absent that writes it lets exactly one of several racing verifications of the same
 * code through, which advancing `lastStep` on the person could not (a read, a check and a whole-object write).
 */
export const TotpSpentStepPayload = t.Object({
	accountId: t.String(),
	exp: t.Number()
});

export type TotpSpentStepPayload = Static<typeof TotpSpentStepPayload>;

/*
 * A link mailed to the person (specs/126 research R4, R7), keyed by the sha256 of its token: the token exists only in
 * the mail. `holder` binds an enrolment link to the place it was asked for — `account:<session uid>` on the account
 * page, the interaction uid at sign-in — so it does nothing in any other browser, and cannot be read aloud to someone
 * who claims to be support. `enrolledAt` (epoch ms) is the factor a `replace` or `disown` link was sent about; either
 * acts only while that same factor is still in place.
 */
export const TotpLinkPayload = t.Object({
	accountId: t.String(),
	bucketId: t.String(),
	purpose: t.Union([
		t.Literal('enrol'),
		t.Literal('replace'),
		t.Literal('reenrol'),
		t.Literal('disown')
	]),
	holder: t.Optional(t.String()),
	enrolledAt: t.Optional(t.Number()),
	exp: t.Number()
});

export type TotpLinkPayload = Static<typeof TotpLinkPayload>;

/*
 * How often one account was mailed an enrolment link, keyed `${bucketId}:${accountId}`: the rate-window record
 * (lib/helpers/rate_window.ts) and `latestLink`, the digest of the newest link, so a resend or a new start kills every
 * earlier one.
 */
export const TotpLinkThrottlePayload = t.Object({
	accountId: t.String(),
	lastSentAt: t.Number(),
	dayCount: t.Number(),
	windowStart: t.Number(),
	latestLink: t.Optional(t.String()),
	exp: t.Number()
});

export type TotpLinkThrottlePayload = Static<typeof TotpLinkThrottlePayload>;
