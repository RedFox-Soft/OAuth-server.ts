/*
 * The largest request body this server reads, on every endpoint (specs/103).
 *
 * Bun's own default is 128 MB, and Elysia parses a body whole before a handler sees it, so without a bound any
 * caller — signed in or not — could make the process hold that much per request. The largest body anything here
 * legitimately sends is a client logo, at most 64 KiB as a data URL (about 88 KB on the wire), so a mebibyte leaves
 * an order of magnitude. SCIM keeps its own, smaller bound (lib/consts/scim.ts).
 *
 * Import-free, because the listener in lib/index.ts and the plugin that refuses a declared length both read it.
 */
export const MAX_REQUEST_BODY_BYTES = 1_048_576;
