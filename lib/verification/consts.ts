// Tunable bounds for the end-user email-verification flow. Kept in one place so the
// challenge logic, the rate limiter, and the tests share a single source of truth.

// Verification link validity (single-use token embedded in the URL).
export const LINK_TTL_SECONDS = 24 * 60 * 60; // ~24h

// Verification code validity (6-digit numeric OTP).
export const CODE_TTL_SECONDS = 15 * 60; // ~15m

// Failed 6-digit code entries tolerated before the code is invalidated and a new
// one must be requested.
export const CODE_MAX_ATTEMPTS = 5;

// Minimum gap between two resend requests for the same account.
export const RESEND_COOLDOWN_SECONDS = 60;

// Resends allowed per account within a rolling 24h window.
export const RESEND_DAILY_CAP = 5;

// Rolling window length the daily cap is measured over.
export const RESEND_WINDOW_SECONDS = 24 * 60 * 60;
