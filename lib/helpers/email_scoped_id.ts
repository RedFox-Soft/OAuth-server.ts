/*
 * The record id shared by every address-scoped storage area — the three areas listed in
 * EMAIL_SCOPED_AREAS (lib/helpers/cascade.ts), which the account cascade destroys by computed id
 * rather than by scanning for an owner field.
 *
 * One function rather than one expression per writer, because the cascade's correctness is exactly
 * "every writer agrees on this string". Three copies of it were tolerable; a fourth, added to serve a
 * third area in that list, is where a divergence stops being hypothetical — and the copy inlined in
 * lib/admin/users-end/routes.ts had already dropped the `toLowerCase()`, harmless only because the
 * MongoDB user store happens to normalise what it stores.
 *
 * THE RULE IS PARITY WITH THE ACCOUNT LOOKUP, not "lower-case it". `findByEmail` is case-insensitive
 * in both adapters (lib/adapters/mongodb/userStore.ts, lib/adapters/memory/userStore.ts), so two
 * spellings that differ only in case resolve to one account and must resolve to one record. Where
 * that matters most is the login throttle: `alice@example.com` has sixteen alphabetic characters, so
 * a key built from the raw submission would give an attacker 2^16 = 65,536 independent counters
 * against one account — and every test written with a lower-case address would still pass. If the
 * lookup ever starts trimming, folding Unicode or stripping `+tags`, this function is what has to
 * follow it.
 */
export function emailScopedId(bucketId: string, email: string): string {
	return `${bucketId}:${email.toLowerCase()}`;
}
