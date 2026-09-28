import { fromJsonSchema } from '@modelcontextprotocol/server';

/*
 * An admin route's TypeBox schema as an MCP tool input schema.
 *
 * The one type assertion between the two libraries, kept here so nothing else repeats it. At runtime an
 * admin schema is plain JSON Schema (test/mcp/schema_bridge.spec.ts proves every one), and
 * `fromJsonSchema` compiles it, so a schema it cannot use fails there. No TypeBox schema is assignable
 * to the SDK's JSON Schema type all the same: TypeBox types `contentEncoding` as any string, the SDK
 * as a fixed list of encodings, and that mismatch holds even for a schema that names no encoding.
 */
export function bridgeSchema(schema: object) {
	return fromJsonSchema(schema as Parameters<typeof fromJsonSchema>[0]);
}
