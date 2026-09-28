import { KindGuard, type Static, type TSchema } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

/*
 * A store's document as its schema describes it, checked on the way out of the datastore.
 *
 * The stores' types used to be interfaces the drivers were told to return — `db.collection<User>()`,
 * `docOf<User>(row)` — which no runtime check stood behind, and in one case knowingly did not hold: a
 * jsonb round trip hands dates back as strings, so the value typed `User` carried strings in its Date
 * fields until a reviver fixed them a line later. The schema is now the declaration and the check.
 *
 * A document that does not match is a defect, not an absence: a stored account that reads as missing
 * would let its email be registered again. So this throws, and the request fails as a 500 that the
 * error store records at its existing capture site — the drift is visible, and nothing proceeds on a
 * record whose shape is unknown.
 */
export function documentOf<S extends TSchema>(
	store: string,
	schema: S,
	value: unknown
): Static<S> {
	const candidate = restored(schema, value);
	if (Value.Check(schema, candidate)) {
		return candidate;
	}
	const first = Value.Errors(schema, candidate).First();
	throw new Error(
		`${store}: a stored document does not match its schema at '${first?.path ?? ''}': ${first?.message ?? 'no match'}`
	);
}

/*
 * A document as its writer wrote it, where a datastore's encoding changed it on the way. Two such
 * changes, each translated back only where the schema says what the value was — never sniffed from the
 * value, which would one day rewrite a field that was always meant to be what it looks like:
 *
 * - BSON has a date type and JSON does not, so PostgreSQL returns as a string what MongoDB returns as a
 *   Date. A string where the schema declares a Date is revived.
 * - The MongoDB driver stores `undefined` as BSON null (its `ignoreUndefined` is off), so an optional
 *   member a writer left undefined reads back as null. Where the schema declares a member optional and
 *   does not admit null, null is that absence, and is read as one.
 *
 * Walks objects, arrays and unions; a value the schema does not describe is left exactly as it came.
 */
function restored(schema: TSchema, value: unknown): unknown {
	if (KindGuard.IsDate(schema)) {
		return typeof value === 'string' ? new Date(value) : value;
	}
	if (KindGuard.IsObject(schema)) {
		if (typeof value !== 'object' || value === null || Array.isArray(value)) {
			return value;
		}
		const document: Record<string, unknown> = { ...value };
		for (const [key, property] of Object.entries(schema.properties)) {
			if (!(key in document)) {
				continue;
			}
			if (
				document[key] === null &&
				KindGuard.IsOptional(property) &&
				!Value.Check(property, null)
			) {
				Reflect.deleteProperty(document, key);
				continue;
			}
			document[key] = restored(property, document[key]);
		}
		return document;
	}
	if (KindGuard.IsArray(schema)) {
		return Array.isArray(value)
			? value.map((item) => restored(schema.items, item))
			: value;
	}
	if (KindGuard.IsUnion(schema)) {
		// The first member that accepts the restored value decides; a Date | null field stays null.
		for (const member of schema.anyOf) {
			const candidate = restored(member, value);
			if (Value.Check(member, candidate)) {
				return candidate;
			}
		}
	}
	return value;
}
