import { t, type TSchema } from 'elysia';

import { SETTINGS_CATALOG, type SettingDescriptor } from './catalog.js';

// A partial map of catalog key -> value. Per-field validation against the catalog
// (types, option membership, invariants) happens in the route handler so failures
// return the admin_error shape rather than a generic TypeBox validation error.
export const UpdateSettingsBody = t.Record(t.String(), t.Unknown());

/* What one setting accepts, as the JSON Schema an agent reads before building a call. */
function publishedType(descriptor: SettingDescriptor): Record<string, unknown> {
	switch (descriptor.type) {
		case 'boolean':
			return { type: 'boolean' };
		case 'string':
			return { type: 'string' };
		case 'number':
			return { type: 'number' };
		case 'enum':
			return { type: 'string', enum: descriptor.options };
		case 'string-array':
			return {
				type: 'array',
				items: descriptor.options
					? { type: 'string', enum: descriptor.options }
					: { type: 'string' }
			};
		case 'json':
			return { type: 'object' };
	}
}

/*
 * What `settings_update` publishes to an agent: the same partial map, with every key the catalog
 * declares typed by name.
 *
 * It exists because the body above says nothing about any setting — deliberately, since the handler is
 * what judges a value — and a tool schema derived from it told an agent nothing either. A client with
 * no type to check a value against sends the text it was handed, so `par.enabled: true` arrived as
 * `"true"` and was refused as not a boolean. Two different clients were seen doing it, and no encoding
 * avoids it from the caller's side: the route wants flat dotted keys carrying real booleans and arrays.
 *
 * This is the one tool whose published schema is not the object its route validates against, and the
 * reason is that the route validates against nothing: the authority on a setting's type is
 * SETTINGS_CATALOG, which the handler and this both read. Deriving the published form from the catalog
 * is therefore closer to the enforced rules than deriving it from the body would be, not further from
 * them. It is published rather than enforced — putting Elysia in front of the handler both coerces
 * values (`richAuthorizationRequests.types: []` became `{}`, matched what was in force and was dropped
 * as no change) and strips the keys the catalog does not declare, which is exactly how an unknown
 * setting and a rejected one stop being distinguishable.
 *
 * Still open. A key the catalog does not declare has to reach the handler to be refused as
 * `unknown setting: <key>`; closing the object would turn a setting retired between releases into a
 * rejected argument with nothing naming it. `test/mcp/settings_schema.spec.ts` holds both halves.
 */
export const PublishedSettingsBody = t.Object(
	Object.fromEntries(
		SETTINGS_CATALOG.map((descriptor) => [
			descriptor.key as string,
			t.Optional(
				t.Unknown({
					...publishedType(descriptor),
					description: descriptor.summary
				}) as TSchema
			)
		])
	),
	{ additionalProperties: true }
);
