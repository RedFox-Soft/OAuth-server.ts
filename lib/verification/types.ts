import type { VerificationMethod } from '../adapters/types.js';

// A pending proof-of-email artifact, bound to one account, stored via the generic
// ModelAdapter with a TTL. `exp` mirrors the adapter's expiry (epoch seconds) and is
// asserted by the test adapter for non-exempt models.
export interface VerificationChallengePayload {
	accountId: string;
	bucketId: string;
	email: string;
	method: VerificationMethod;
	// Present only for the code method: hash of the 6-digit code (plaintext is never
	// persisted).
	codeHash?: string;
	// Failed code entries so far; the code is invalidated once this reaches the cap.
	attempts: number;
	exp: number;
}

// Per-account resend rate-limit state. Keyed by `${bucketId}:${email}` so it survives
// challenge rotation and the daily cap still applies across resends.
export interface VerificationResendPayload {
	lastSentAt: number;
	dayCount: number;
	windowStart: number;
	// Pointer to the account's current outstanding challenge, so a resend can supersede
	// it. Survives challenge rotation because this record outlives any single challenge.
	challengeId?: string;
	exp: number;
}
