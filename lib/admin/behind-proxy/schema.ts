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

const Rule = t.Object(
	{
		path: t.String({ minLength: 1, maxLength: 512 }),
		who: Who
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
		rules: t.Optional(t.Array(Rule, { maxItems: 50 }))
	},
	{ additionalProperties: false }
);
