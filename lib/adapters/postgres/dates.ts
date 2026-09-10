/*
 * Restoring `Date` values a jsonb round trip turned into strings.
 *
 * BSON has a date type and JSON does not. So a store that writes `{ expiresAt: new Date() }` and
 * reads it back gets a `Date` from MongoDB and a string from PostgreSQL — and the difference does not
 * announce itself at the boundary. It surfaces later, as `record.expiresAt.getTime is not a function`
 * somewhere that looks unrelated, or worse as a comparison between a string and a number that is
 * simply always false.
 *
 * The same shape of defect as the `Buffer`/`Binary` one that stopped the server booting: a driver's
 * representation leaking past the adapter into code whose guard was written for the other one.
 * Translating back is the adapter's job, here as there.
 *
 * Every caller names its date fields explicitly rather than having them sniffed out of the value.
 * Guessing — "this string parses as a date, so it was one" — would eventually rewrite a field that
 * was always meant to be text, and the list at each call site doubles as documentation of which
 * fields a record carries dates in.
 */
export function reviveDates<T extends object>(
	doc: T,
	keys: readonly (keyof T)[]
): T {
	const revived = { ...doc };

	for (const key of keys) {
		const value = revived[key];
		if (typeof value === 'string') {
			/* The value came out of a jsonb column as a string; the key list is the assertion that it
			 * went in as a Date, which no runtime check can establish. */
			revived[key] = new Date(value) as T[keyof T];
		}
	}

	return revived;
}
