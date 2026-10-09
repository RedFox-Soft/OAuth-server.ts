import { Value } from '@sinclair/typebox/value';
import type { Static, TSchema } from '@sinclair/typebox';
import { OIDCProviderError } from 'lib/helpers/errors.ts';
import { jsonText } from 'lib/helpers/_/json_text.ts';

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
		`unexpected shape at '${first?.path ?? ''}': ${first?.message ?? 'no match'} — ${jsonText(value)?.slice(0, 300) ?? 'undefined'}`
	);
}

// A value the test needs present — a header, a query parameter, a match — failing with what was missing.
export function present<T>(value: T | null | undefined, what: string): T {
	if (value === null || value === undefined) {
		throw new Error(`expected ${what}`);
	}
	return value;
}

/*
 * An endpoint's error event carries whatever its handler threw — a protocol error, or one of Elysia's own
 * (not found, validation) — so a test reading `error_detail` first asserts which it got.
 */
export function providerError(value: unknown): OIDCProviderError {
	if (!(value instanceof OIDCProviderError)) {
		throw new Error(`expected a protocol error, got ${String(value)}`);
	}
	return value;
}

/* A response body as text: a page as itself, anything else as the JSON it is rather than "[object Object]". */
export function textOf(value: unknown): string {
	return typeof value === 'string' ? value : (jsonText(value) ?? '');
}
