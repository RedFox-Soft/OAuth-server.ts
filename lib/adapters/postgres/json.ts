/*
 * Reading a `jsonb` column.
 *
 * Bun's SQL client decodes a jsonb column into a JavaScript value correctly, and encodes a JavaScript
 * object into jsonb correctly. What it does NOT accept is a pre-stringified object: passing
 * `${JSON.stringify(doc)}::jsonb` sends the text as a JSON *string*, and the cast faithfully stores a
 * jsonb string containing JSON rather than a jsonb object. Every `doc->>'field'` predicate against
 * such a row then matches nothing, silently.
 *
 * This function exists to make that failure loud, and its first version did the exact opposite. It
 * parsed the string instead — which round-tripped every value perfectly and hid the defect completely.
 * Writes and reads agreed, provisioning and seeding both reported success, and only SQL-level
 * predicates were broken, so the first symptom was a login that could not find a user plainly present
 * in the table. A tolerant decoder in front of an encoding bug is indistinguishable from correct
 * behaviour right up until something queries inside the document.
 *
 * So a string is an error here, not an input to repair.
 */
function decoded<T>(value: unknown, column: string): T | undefined {
	if (value === undefined || value === null) return undefined;

	if (typeof value === 'string') {
		throw new Error(
			`the '${column}' column holds a jsonb string rather than an object, which means it was ` +
				'written with a pre-stringified value — pass the object itself, not JSON.stringify(...)'
		);
	}

	return value as T;
}

/* The document column of a row. Named for the two column names the schema uses, so a call site reads
 * as what it fetches: model areas keep their record in `payload`, everything else in `doc`. */
export function docOf<T>(row: unknown): T | undefined {
	return decoded<T>((row as { doc?: unknown } | undefined)?.doc, 'doc');
}

export function payloadOf<T>(row: unknown): T | undefined {
	return decoded<T>(
		(row as { payload?: unknown } | undefined)?.payload,
		'payload'
	);
}
