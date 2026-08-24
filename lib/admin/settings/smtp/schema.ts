import { t } from 'elysia';

// Sentinel returned in place of the stored password and accepted back on PUT to mean
// "leave the password unchanged" (so the UI never has to hold the real secret).
export const SMTP_PASSWORD_MASK = '********';

export const UpdateSmtpBody = t.Object({
	host: t.String(),

	/*
	 * Deliberately not `t.Integer()`. Elysia overrides TypeBox's integer with a *decoder*: it renders as
	 * `anyOf: [{ type: 'string', format: 'integer', default: 0 }, { type: 'integer' }]` so a field that
	 * arrives as the string "587" still validates. That coercion is invisible until the schema leaves
	 * Elysia — and this one does, because it is also the `smtp_settings_update` tool's published input
	 * schema (`lib/mcp/catalogue.ts`). There Ajv compiles it and logs `unknown format "integer" ignored
	 * in schema at path "#/properties/port/anyOf/0"` at every boot, for a format only Elysia's own
	 * registry declares, and an agent reads a `default: 0` this field does not have.
	 *
	 * `multipleOf: 1` says "integer" in plain JSON Schema, which is what the MCP surface promises to
	 * publish. TypeBox's real `Type.Integer` is not reachable through Elysia's `t`, or it would be used
	 * here instead. The range belongs to the handler, next to the other field rules.
	 *
	 * The console must therefore send a number: antd's `<Input type="number">` yields a *string*, and
	 * relying on the coercion to fix that was what hid the mismatch. The form uses `InputNumber`.
	 */
	port: t.Number({ multipleOf: 1 }),
	secure: t.Boolean(),
	username: t.String(),
	password: t.String(),
	fromName: t.String(),
	fromEmail: t.String()
});
