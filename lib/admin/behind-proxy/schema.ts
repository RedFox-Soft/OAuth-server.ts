import { t } from 'elysia';

/*
 * Bodies of the routes for apps behind a proxy (specs/122). Kept apart from the routes because lib/mcp/catalogue.ts
 * imports schema modules and must never import a route module. Closed, so a field this server does not know is
 * refused rather than silently ignored.
 *
 * Shapes only: whether an address is one an app can have, a path is unambiguous, a group is this project's, are
 * rules the service decides and explains, so each refusal has one definition reachable from the console and an
 * agent. The edge word `groups` is translated to the stored `groupIds` by the service's explicit projection.
 */

const GroupIds = t.Array(t.String({ minLength: 1, maxLength: 64 }), {
	maxItems: 50
});

const Who = t.Union([
	t.Object(
		{ kind: t.Literal('groups'), groups: GroupIds },
		{ additionalProperties: false }
	),
	t.Object({ kind: t.Literal('project') }, { additionalProperties: false }),
	t.Object(
		{ kind: t.Literal('public'), subtree: t.Boolean() },
		{ additionalProperties: false }
	),
	t.Object({ kind: t.Literal('none') }, { additionalProperties: false })
]);

/*
 * Conditions at the proxy (specs/124 contracts/admin-api.md), at the edge: what a rule or an API asks beyond "who".
 * Shapes and bounds only; canonical ranges, selectable attributes and the project's groups are the service's
 * (lib/admin/conditions.ts), so each refusal names the path and the value.
 */
const closed = { additionalProperties: false } as const;
const RangeLines = t.Array(t.String({ minLength: 1, maxLength: 60 }), {
	maxItems: 100
});
/* Whole numbers by `multipleOf`, not `t.Integer`, whose coercion format the MCP schema bridge refuses. */
const Minute = t.Number({ minimum: 0, maximum: 1439, multipleOf: 1 });
export const TimeWindowBody = t.Object(
	{
		days: t.Array(t.Number({ minimum: 0, maximum: 6, multipleOf: 1 }), {
			minItems: 1,
			maxItems: 7
		}),
		start: Minute,
		end: Minute
	},
	closed
);
const NetworkBody = t.Object(
	{ kind: t.Literal('network'), only: RangeLines, not: RangeLines },
	closed
);
const TimeBody = t.Object(
	{
		kind: t.Literal('time'),
		windows: t.Array(TimeWindowBody, { minItems: 1, maxItems: 7 })
	},
	closed
);
const AttributeBody = t.Object(
	{
		kind: t.Literal('attribute'),
		attribute: t.String({ minLength: 1, maxLength: 70 }),
		values: t.Array(t.String({ minLength: 1, maxLength: 200 }), {
			minItems: 1,
			maxItems: 50
		})
	},
	closed
);
const FreshBody = t.Object(
	{
		kind: t.Literal('fresh'),
		maxAgeMinutes: t.Number({ minimum: 5, maximum: 1440, multipleOf: 1 })
	},
	closed
);
const GroupBody = t.Object(
	{ kind: t.Literal('group'), groups: GroupIds },
	closed
);
/* An app's rule: its groups live in "who", and a fresh sign-in is the app's session's to ask for. */
export const AppConditionBody = t.Union([
	NetworkBody,
	TimeBody,
	AttributeBody,
	FreshBody
]);
/* An API's access: no session to sign in again to, and its groups are a condition. */
export const ApiConditionBody = t.Union([
	GroupBody,
	AttributeBody,
	NetworkBody,
	TimeBody
]);
/* An IANA zone, or null to clear it. */
export const TimeZoneBody = t.Union([t.String({ maxLength: 64 }), t.Null()]);

const Rule = t.Object(
	{
		path: t.String({ minLength: 1, maxLength: 512 }),
		who: Who,
		conditions: t.Optional(t.Array(AppConditionBody, { maxItems: 4 }))
	},
	{ additionalProperties: false }
);

const Name = t.String({ minLength: 1, maxLength: 100 });
/* A browser's address bar is a fair thing to paste; the service keeps only the origin. */
const Address = t.String({ minLength: 1, maxLength: 2048 });
const ProxyKind = t.Union([
	t.Literal('caddy'),
	t.Literal('traefik'),
	t.Literal('nginx')
]);

export const CreateBehindProxyAppBody = t.Object(
	{
		name: Name,
		address: Address,
		proxyKind: ProxyKind,
		/* Who may open the app at all: the rule for `/`, which every app starts with. */
		rootGroups: GroupIds
	},
	{ additionalProperties: false }
);

/* `rules` replaces the whole list, because the console saves a form together; its `/` rule must remain. */
export const UpdateBehindProxyAppBody = t.Object(
	{
		name: t.Optional(Name),
		address: t.Optional(Address),
		proxyKind: t.Optional(ProxyKind),
		rules: t.Optional(t.Array(Rule, { maxItems: 50 })),
		/* The zone the app's time conditions and refusal pages read the clock in (specs/124). */
		timeZone: t.Optional(TimeZoneBody)
	},
	{ additionalProperties: false }
);
