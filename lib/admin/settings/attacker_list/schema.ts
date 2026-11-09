import { t } from 'elysia';

/*
 * The attacker list card's answer (specs/125 contracts/admin-api.md). Its own module, not inline in the route,
 * because the MCP catalogue imports schema modules and must never import a route module. It never carries an
 * address: what the list holds is FoxTrust's, and what this server saw is nobody's to read here.
 */
export const AttackerListState = t.Union([
	t.Literal('off'),
	t.Literal('not-yet'),
	t.Literal('current'),
	t.Literal('out-of-date'),
	t.Literal('unknown-format')
]);

export const AttackerListStatusResponse = t.Object({
	enabled: t.Boolean(),
	effective: t.Boolean(),
	state: AttackerListState,
	held: t.Union([
		t.Object({
			version: t.String(),
			builtAt: t.String(),
			validUntil: t.String(),
			entries: t.Number()
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
	scope: t.Literal('process'),
	projectsUsing: t.Object({ count: t.Number(), refuse: t.Number() })
});
