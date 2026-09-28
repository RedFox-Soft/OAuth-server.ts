import { Value } from '@sinclair/typebox/value';
import type { Static, TSchema } from '@sinclair/typebox';

/*
 * Data a test reads from outside the type system — a JSON body, a parsed page prop, a raw store record —
 * as the shape the test expects, checked rather than claimed. `Response.json()` answers `any`, so a
 * type written on it is a claim nobody verifies; a mismatch here fails at once and says where, instead
 * of surfacing later as a read of `undefined`. Objects admit members the schema does not name, so a
 * schema states only what the test reads.
 */
export function shaped<T extends TSchema>(
	schema: T,
	value: unknown
): Static<T> {
	if (Value.Check(schema, value)) {
		return value;
	}
	const first = Value.Errors(schema, value).First();
	throw new Error(
		`unexpected shape at '${first?.path ?? ''}': ${first?.message ?? 'no match'} — ${JSON.stringify(value)?.slice(0, 300)}`
	);
}

// A value the test needs present — a header, a query parameter, a match — failing with what was missing.
export function present<T>(value: T | null | undefined, what: string): T {
	if (value === null || value === undefined) {
		throw new Error(`expected ${what}`);
	}
	return value;
}
