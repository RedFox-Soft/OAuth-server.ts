// Tunable bounds for the end-user second-factor flow. Kept in one place so the algorithm, the
// enrolment lifecycle, the rate limiter and the tests share a single source of truth — the
// arrangement lib/verification/consts.ts settled on.

// RFC 6238 §4 default time step. Every widely deployed authenticator app assumes it, and the
// `period=` parameter of the otpauth:// URI is as widely ignored as `algorithm=`.
export const STEP_SECONDS = 30;

// RFC 4226 §5.3 truncation length. Six is what an authenticator app displays.
export const DIGITS = 6;

// Steps either side of the current one that are still accepted, tolerating ordinary clock drift.
// RFC 6238 §5.2 calls one step "a good balance"; a wider band multiplies the guess space linearly
// for no gain, because the replay guard already caps how long any single code stays usable.
export const DRIFT_STEPS = 1;

// How long an offered-but-unconfirmed enrolment secret survives. Matches the verification flow's
// CODE_TTL_SECONDS: an enrolment is a single sitting, and a secret nobody proved should not outlive it.
export const ENROLLMENT_TTL_SECONDS = 15 * 60;

// Failed code entries tolerated within one sign-in attempt before it refuses further submissions.
// Matches lib/verification/consts.ts CODE_MAX_ATTEMPTS.
export const MAX_ATTEMPTS_PER_INTERACTION = 5;

/*
 * Failed entries tolerated per account across sign-in attempts, within ACCOUNT_WINDOW_SECONDS.
 *
 * The per-interaction cap alone is defeated by starting a new interaction, which costs an attacker
 * one request. With DRIFT_STEPS = 1 there are 3 acceptable codes out of 10^6 at any moment, so 10
 * guesses per window is a ~3-in-10^5 chance of landing one — the arithmetic is written down here so
 * it can be re-checked if either number moves.
 */
export const ACCOUNT_FAILURE_CAP = 10;

// The rolling window the per-account cap is measured over, and the TTL of the record holding it.
export const ACCOUNT_WINDOW_SECONDS = 15 * 60;

// RFC 4226 §4 R6 recommends at least 128 bits and 160 for HMAC-SHA1; 160 is also what every
// published test vector uses. Base32-encodes to 32 characters, which a person can retype.
export const SECRET_BYTES = 20;
