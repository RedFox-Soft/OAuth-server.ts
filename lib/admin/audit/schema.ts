import { t } from 'elysia';

/*
 * Everything arrives as a string, since these are query parameters.
 *
 * Lifted out of `routes.ts` so the MCP tool catalogue can reuse the exact object the route validates
 * against without importing the route module — which reaches the adapters and from there
 * `lib/adapters/mongodb/db.ts`, a module that connects at import time. Same reason
 * `lib/consts/admin_audit_routes.ts` imports nothing.
 */
export const AuditQuery = t.Object({
	actor: t.Optional(t.String()),
	action: t.Optional(t.String()),
	targetType: t.Optional(t.String()),
	targetId: t.Optional(t.String()),
	targetScope: t.Optional(t.String()),
	/* Which surface the action arrived on: absent means the console. */
	viaSurface: t.Optional(t.String()),
	viaClientId: t.Optional(t.String()),
	from: t.Optional(t.String()),
	to: t.Optional(t.String()),
	page: t.Optional(t.String()),
	pageSize: t.Optional(t.String())
});

/*
 * Checked against the raw URL by the route, not against the validated `query` object, because Elysia
 * only lifts *declared* keys out of the query string — an undeclared one never reaches the schema and
 * `additionalProperties: false` cannot refuse it. Derived from the schema above so the two cannot
 * disagree: a filter added to one is added to the other.
 */
export const ALLOWED_AUDIT_PARAMS: ReadonlySet<string> = new Set(
	Object.keys(AuditQuery.properties)
);
