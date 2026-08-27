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
	exp: t.Number()
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
	exp: t.Number()
});

export type TotpAttemptPayload = Static<typeof TotpAttemptPayload>;
