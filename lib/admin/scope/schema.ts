import { t } from 'elysia';

/*
 * Its own module rather than living beside the route, because `lib/mcp/catalogue.ts` imports the same
 * object the route validates against — and the catalogue may never import a route module. A route
 * module reaches the adapters and from there `lib/adapters/mongodb/db.ts`, which connects at import
 * time and is unloadable under test.
 */
export const SwitchScopeBody = t.Object({
	groupId: t.String({ minLength: 1 })
});
