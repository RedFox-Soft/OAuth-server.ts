import { t } from 'elysia';

/*
 * The monthly active users read surface (specs/076). Everything arrives as a string, since these are query
 * parameters.
 *
 * Lifted out of `routes.ts` so the MCP tool catalogue can reuse the exact objects the routes validate against
 * without importing the route module — which reaches the adapters and from there `lib/adapters/mongodb/db.ts`,
 * a module that connects at import time.
 */
export const BucketActivityQuery = t.Object({
	/* `YYYY-MM`, UTC. Absent means the current month. */
	month: t.Optional(t.String())
});

export const ActivityOverviewQuery = t.Object({
	/* `YYYY-MM`, UTC. Absent means the current month; the month before it is answered beside it. */
	month: t.Optional(t.String())
});

/*
 * Checked against the raw URL by the routes, because Elysia only lifts declared keys out of the query string:
 * a mistyped `mont=` would otherwise be dropped and answered as the current month — a wrong figure wearing a
 * 200 on a surface a price will be read from. Derived from the schemas so the two cannot disagree.
 */
export const ALLOWED_BUCKET_ACTIVITY_PARAMS: ReadonlySet<string> = new Set(
	Object.keys(BucketActivityQuery.properties)
);

export const ALLOWED_ACTIVITY_OVERVIEW_PARAMS: ReadonlySet<string> = new Set(
	Object.keys(ActivityOverviewQuery.properties)
);
