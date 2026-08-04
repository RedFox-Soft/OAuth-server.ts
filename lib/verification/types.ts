import { Type as t, type Static } from '@sinclair/typebox';

import type { VerificationMethod } from '../adapters/types.js';

// These two payloads are TypeBox schemas rather than plain interfaces so the storage-ownership drift
// guard can read their fields at runtime, as it does for every other model area: an interface erases,
// and `VerificationChallenge.accountId` is one of the areas a deleted account's cascade sweeps. The
// records are still written straight through `adapter('VerificationChallenge')` and never through a
// model class, so nothing validates them against these schemas — they exist to be introspected, not to
// gate a write.

const method = t.Union([t.Literal('link'), t.Literal('code')]);

/*
 * Compile-time proof that the runtime union above and the `VerificationMethod` alias cannot drift
 * apart — the same device `ModelPayloadMapMatchesInventory` uses in lib/adapters/modelTypes.ts, and for
 * the same reason: only a value can be read at runtime, so the value is the source and the check is
 * what keeps the alias honest.
 */
export type VerificationMethodMatchesSchema = [
	Exclude<Static<typeof method>, VerificationMethod>,
	Exclude<VerificationMethod, Static<typeof method>>
] extends [never, never]
	? true
	: never;

// A pending proof-of-email artifact, bound to one account, stored via the generic
// ModelAdapter with a TTL. `exp` mirrors the adapter's expiry (epoch seconds) and is
// asserted by the test adapter for non-exempt models.
export const VerificationChallengePayload = t.Object({
	accountId: t.String(),
	bucketId: t.String(),
	email: t.String(),
	method,
	// Present only for the code method: hash of the 6-digit code (plaintext is never
	// persisted).
	codeHash: t.Optional(t.String()),
	// Failed code entries so far; the code is invalidated once this reaches the cap.
	attempts: t.Number(),
	exp: t.Number()
});

export type VerificationChallengePayload = Static<
	typeof VerificationChallengePayload
>;

// Per-account resend rate-limit state. Keyed by `${bucketId}:${email}` so it survives
// challenge rotation and the daily cap still applies across resends.
export const VerificationResendPayload = t.Object({
	lastSentAt: t.Number(),
	dayCount: t.Number(),
	windowStart: t.Number(),
	// Pointer to the account's current outstanding challenge, so a resend can supersede
	// it. Survives challenge rotation because this record outlives any single challenge.
	challengeId: t.Optional(t.String()),
	exp: t.Number()
});

export type VerificationResendPayload = Static<
	typeof VerificationResendPayload
>;
