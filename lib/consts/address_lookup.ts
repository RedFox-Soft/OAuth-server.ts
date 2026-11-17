/*
 * Looking up the network owner and location of the addresses people's activity records (specs/136), declared once.
 *
 * Import-free, like every lib/consts/ declaration. FoxTrust's contracts of 2026-11-17 fix the destinations and the
 * limits (foxtrust specs/042 contracts/instance-keys.md and batch-lookup.md).
 */

/*
 * Both destinations are compiled in with no override and no environment variable, as the usage report's is (owner,
 * 2026-10-28): an instance that never upgrades keeps calling these, so FoxTrust may never move them.
 */
export const REGISTRATION_DESTINATION =
	'https://api.foxtrust.dev/v1/foxauth/instance-keys';
export const BATCH_DESTINATION = 'https://api.foxtrust.dev/v1/ip/batch';

export const REGISTRATION_FORMAT = 1;

/* The first line of what a registration signs; FoxTrust refuses a signature over anything else. */
export const SIGNED_PREFIX = 'foxtrust-instance-key-v1';

/* FoxTrust's limit for one batch request. */
export const BATCH_MAX = 100;

/*
 * Per flush (research R7): three batches, 200 ms apart so a key's five requests a second are never exceeded, each
 * given 2.5 s (FoxTrust reads within 1 s), and none started once the flush has waited 3 s. A slow FoxTrust then
 * delays a minute's activity by at most 3 s and never a request.
 */
export const BATCHES_PER_FLUSH = 3;
export const BATCH_SPACING_MS = 200;
export const BATCH_TIMEOUT_MS = 2500;
export const LOOKUP_FLUSH_BUDGET_MS = 3000;

export const REGISTRATION_TIMEOUT_MS = 10_000;

/*
 * FoxTrust's standing needs the first report carrying the instance key to be 7 UTC days old (research R10): asking
 * earlier only collects "not yet".
 */
export const FIRST_REGISTRATION_AFTER_DAYS = 7;

/*
 * After "muted" or "key mismatch", which only FoxTrust's operator can lift: once a week, so a lift takes effect
 * without anyone here doing anything, never daily as FoxTrust asks (research R11).
 */
export const STOPPED_RETRY_DAYS = 7;

/*
 * A process remembers this many answers per UTC day. A key gets 1 000 answers a day, so the bound is never reached on
 * a normal day; it guards memory against a FoxTrust that misbehaves (research R8).
 */
export const LOOKUP_CACHE_MAX = 5000;

/* What a row keeps of a name FoxTrust returns; longer is cut, never refused. */
export const LOOKUP_TEXT_MAX = 200;
export const REGION_CODE_MAX = 8;

/* The body fields FoxTrust may name in a 400; any other name is dropped, never stored. */
export const REGISTRATION_FIELDS = [
	'format',
	'instanceId',
	'instanceKey',
	'issuedAt',
	'nonce',
	'signature'
] as const;
export type RegistrationField = (typeof REGISTRATION_FIELDS)[number];
