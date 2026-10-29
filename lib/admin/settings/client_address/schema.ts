import { t } from 'elysia';

/*
 * The caller address check (specs/115 contracts/admin-surface.md). Its own module, not inline in the
 * route, because the MCP catalogue imports schema modules and must never import a route module.
 *
 * Header names only, never values: the operator needs to know which proxy spoke, and the values are the
 * caller's own address, already shown as `attributed` where it was believed.
 */
export const CallerAddressCheckResponse = t.Object({
	source: t.Union([
		t.Literal('automatic'),
		t.Literal('direct'),
		t.Literal('fly'),
		t.Literal('cloudflare'),
		t.Literal('listed')
	]),
	attributed: t.Object({
		address: t.String(),
		from: t.Union([
			t.Literal('connection'),
			t.Literal('x-forwarded-for'),
			t.Literal('fly-client-ip'),
			t.Literal('unattributed')
		])
	}),
	connection: t.Union([t.String(), t.Null()]),
	forwardedHeaders: t.Array(t.String()),
	warning: t.Union([
		t.Null(),
		t.Literal('fly-header-missing'),
		t.Literal('forwarded-ignored'),
		t.Literal('fly-header-present')
	])
});
