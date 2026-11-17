import { t } from 'elysia';

/*
 * The address lookup card's answer (specs/136 contracts/admin-api.md §1). Its own module, not inline in the route,
 * because the MCP catalogue imports schema modules and must never import a route module. No member holds a key: the
 * FoxTrust key and the private half of the instance key are never part of it.
 */
const Nullable = <T extends Parameters<typeof t.Union>[0][number]>(schema: T) =>
	t.Union([schema, t.Null()]);

export const AddressLookupStatusResponse = t.Object({
	setting: t.Boolean(),
	state: t.Union([
		t.Literal('off'),
		t.Literal('key-unreadable'),
		t.Literal('on'),
		t.Literal('stopped'),
		t.Literal('reporting-off'),
		t.Literal('waiting')
	]),
	instanceId: t.String(),
	instanceKey: Nullable(t.String()),
	key: Nullable(
		t.Object({
			receivedAt: t.String(),
			dailyQuota: t.Number(),
			burst: t.Number()
		})
	),
	today: Nullable(
		t.Object({
			day: t.String(),
			limit: Nullable(t.Number()),
			remaining: Nullable(t.Number()),
			usedUp: t.Boolean()
		})
	),
	registration: t.Object({
		firstKeyReportAt: Nullable(t.String()),
		lastTriedAt: Nullable(t.String()),
		lastAnswer: Nullable(
			t.Union([
				t.Literal('key'),
				t.Literal('not_yet'),
				t.Literal('muted'),
				t.Literal('key_mismatch'),
				t.Literal('invalid'),
				t.Literal('limited'),
				t.Literal('unavailable'),
				t.Literal('unreachable')
			])
		),
		lastInvalidField: Nullable(t.String()),
		nextTryAfter: Nullable(t.String())
	}),
	stopped: Nullable(t.Union([t.Literal('muted'), t.Literal('key_mismatch')]))
});
