import { t } from 'elysia';

/*
 * The attack reporting card's answer (specs/114 contracts/admin-surface.md). Its own module, not inline in the
 * route, because the MCP catalogue imports schema modules and must never import a route module.
 *
 * `report` is left open: it is whatever was last sent, byte for byte, and its shape is the wire contract's to
 * define, not this answer's.
 */
export const AttackReportsStatusResponse = t.Object({
	enabled: t.Boolean(),
	offBecause: t.Optional(
		t.Union([t.Literal('setting'), t.Literal('no-datastore')])
	),
	setting: t.Boolean(),
	lastDeliveredAt: t.Union([t.String(), t.Null()]),
	report: t.Unknown(),
	reportIsPreview: t.Boolean()
});
