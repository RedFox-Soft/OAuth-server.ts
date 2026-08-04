import { Type as t, type Static } from '@sinclair/typebox';

// These two payloads are TypeBox schemas rather than plain interfaces so the storage-ownership drift guard
// can read their fields at runtime, as it does for every other model area: an interface erases, and
// `PasswordResetChallenge.accountId` is one of the areas a deleted account's cascade sweeps. The records
// are written straight through `adapter('PasswordResetChallenge')` and never through a model class, so
// nothing validates them against these schemas — they exist to be introspected, not to gate a write.

/*
 * A pending authorisation to change one account's password.
 *
 * The record's id is the SHA-256 digest of the token that went out in the email, and the token appears in
 * no field here. That is the one place this deliberately departs from VerificationChallenge, whose record
 * id *is* its emailed token: adequate for proving an address, and not for a secret that grants a
 * credential change, since a leaked datastore would then hand over password-change authority over every
 * account with an outstanding request.
 */
export const PasswordResetChallengePayload = t.Object({
	accountId: t.String(),
	bucketId: t.String(),
	// Lowercased address the mail went to; needed to compose the throttle id on consumption. Never echoed
	// back to a browser.
	email: t.String(),
	/*
	 * Epoch seconds. Mirrors the adapter's expiry *and* is compared to now on every read: MongoDB's TTL
	 * monitor deletes lazily, so an expired record can still be found for a minute or more, which for a
	 * takeover-capable secret is a minute of extra credential validity.
	 */
	exp: t.Number()
});

export type PasswordResetChallengePayload = Static<
	typeof PasswordResetChallengePayload
>;

/*
 * Per-address request counters. Keyed by `${bucketId}:${email}` so the daily cap survives challenge
 * rotation — counters folded into the challenge record would reset on every supersession, which is the one
 * thing a cap must not do.
 *
 * Written only when a message is actually sent, so an address that resolves to no account leaves nothing
 * here to read.
 */
export const PasswordResetThrottlePayload = t.Object({
	lastSentAt: t.Number(),
	dayCount: t.Number(),
	windowStart: t.Number(),
	// The account's current outstanding challenge id (a digest, not a token), so a new request can
	// supersede it. Optional because a window outlives any single challenge.
	challengeId: t.Optional(t.String()),
	exp: t.Number()
});

export type PasswordResetThrottlePayload = Static<
	typeof PasswordResetThrottlePayload
>;
