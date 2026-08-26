import { t } from 'elysia';

/*
 * Everything arrives as a string, since these are query parameters.
 *
 * Lifted out of `routes.ts` so the MCP tool catalogue can reuse the exact object the route validates
 * against without importing the route module — which reaches the adapters and from there
 * `lib/adapters/mongodb/db.ts`, a module that connects at import time.
 *
 * One schema serves the listing, the purge preview and the purge itself. That sharing is not tidiness:
 * it is what makes a preview provably describe the same set the purge will remove, because there is no
 * second definition of what the filters mean.
 */
export const ErrorQuery = t.Object({
	errorCode: t.Optional(t.String()),
	route: t.Optional(t.String()),
	surface: t.Optional(t.String()),
	status: t.Optional(t.String()),
	clientId: t.Optional(t.String()),
	/* Matches an actor id or an email, so a deleted administrator's records stay findable. */
	actor: t.Optional(t.String()),
	from: t.Optional(t.String()),
	to: t.Optional(t.String()),
	limit: t.Optional(t.String()),
	offset: t.Optional(t.String())
});

/* The window-only shape the summary takes: no paging, and no filters it could not aggregate over. */
export const ErrorSummaryQuery = t.Object({
	from: t.Optional(t.String()),
	to: t.Optional(t.String())
});

/*
 * Checked against the raw URL by the route, not against the validated `query` object, because Elysia
 * only lifts *declared* keys out of the query string — an undeclared one never reaches the schema and
 * `additionalProperties: false` cannot refuse it. Derived from the schemas above so the two cannot
 * disagree: a filter added to one is added to the other.
 *
 * It matters more here than on most endpoints, for the reason the audit trail's equivalent gives: a
 * mistyped filter that is silently dropped answers with the *unfiltered* set — a wrong answer wearing
 * a 200, on a surface whose whole purpose is to be trusted about what happened. On the purge it would
 * be worse still, because the set it describes is the set it destroys.
 */
export const ALLOWED_ERROR_PARAMS: ReadonlySet<string> = new Set(
	Object.keys(ErrorQuery.properties)
);

export const ALLOWED_ERROR_SUMMARY_PARAMS: ReadonlySet<string> = new Set(
	Object.keys(ErrorSummaryQuery.properties)
);
