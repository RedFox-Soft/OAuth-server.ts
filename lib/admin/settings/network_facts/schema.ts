import { t } from 'elysia';

/*
 * The network facts card's answer (specs/129 contracts/admin-and-proxy.md). Its own module, not inline in the route,
 * because the MCP catalogue imports schema modules and must never import a route module.
 */
export const NetworkFactsState = t.Union([
	t.Literal('off'),
	t.Literal('not-yet'),
	t.Literal('current'),
	t.Literal('stale')
]);

export const NetworkFactsStatusResponse = t.Object({
	enabled: t.Boolean(),
	state: NetworkFactsState,
	held: t.Union([
		t.Object({
			fullVersion: t.String(),
			deltaVersion: t.Union([t.String(), t.Null()]),
			builtAt: t.String(),
			ageSeconds: t.Number(),
			ranges: t.Number()
		}),
		t.Null()
	]),
	lastCheckAt: t.Union([t.String(), t.Null()]),
	lastAcceptedAt: t.Union([t.String(), t.Null()]),
	lastProblem: t.Union([
		t.Object({
			kind: t.String(),
			at: t.String(),
			consecutive: t.Number()
		}),
		t.Null()
	]),
	unreadableReads: t.Number(),
	scope: t.Literal('process')
});

/* The short form every administrator sees beside conditions (FR-009, FR-028). */
export const NetworkFactsSummary = t.Object({
	state: NetworkFactsState,
	builtAt: t.Union([t.String(), t.Null()])
});
