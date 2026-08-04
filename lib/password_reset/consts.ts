// Tunable bounds for the self-service password reset. Kept in one place so the challenge logic, the rate
// limiter, and the tests share a single source of truth — the same arrangement lib/verification/consts.ts
// has, and deliberately not the same numbers.

/*
 * Reset link validity. A quarter of the shortest thing the verification flow issues, because a reset
 * secret *changes a credential* where a verification secret only proves an address: long enough to
 * survive a mail queue and a distracted user, short enough that a mailbox read hours later is worthless.
 */
export const RESET_TTL_SECONDS = 60 * 60; // ~1h

// Minimum gap between two reset requests for the same address in the same bucket.
export const REQUEST_COOLDOWN_SECONDS = 60;

// Reset emails allowed per address within a rolling 24h window.
export const REQUEST_DAILY_CAP = 5;

/*
 * Rolling window the cap is measured over, and the throttle record's own TTL — a window that outlived
 * its meaning would keep refusing a legitimate request.
 */
export const REQUEST_WINDOW_SECONDS = 24 * 60 * 60;
