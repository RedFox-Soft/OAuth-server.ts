import { t } from 'elysia';

import { ApiConditionBody, TimeZoneBody } from '../behind-proxy/schema.js';

/*
 * Bodies for the protected-resource routes.
 *
 * In this module rather than inline in `routes.ts`, and that is a constraint rather than a
 * preference: `lib/mcp/catalogue.ts` imports schema modules so an agent reads the very schema the
 * route enforces, and it must never import a route module — a route module reaches the adapters and
 * from there a database module that connects at import time.
 *
 * The identifier and the scope list are typed only loosely here. Both have rules a TypeBox pattern
 * could not express usefully — canonical form, instance-wide uniqueness, the reserved administrative
 * audience, the omnibus-scope refusal — and each rejection needs to name what was wrong with which
 * value. Same reasoning as `corsOrigins` in the clients schema: the check runs in the handler so the
 * answer arrives in the admin error shape with something an operator can act on.
 */
/*
 * What one scope lets an app do, as the consent page says it to the person deciding. `kind` says whether
 * the app merely sees something or acts; absent, the page says "act", because understating what an app
 * may do is the mistake that matters on that page.
 */
const ScopeDescriptionBody = t.Object(
	{
		description: t.String({ minLength: 1, maxLength: 200 }),
		kind: t.Optional(t.Union([t.Literal('see'), t.Literal('act')]))
	},
	{ additionalProperties: false }
);

const ScopeDescriptions = t.Record(t.String(), ScopeDescriptionBody);

/*
 * Who checks the tokens the API receives (specs/123). The rules a closed schema cannot state usefully — an https
 * identifier for the proxy, a project with an address of its own — are the handler's, so the refusal names them.
 */
const CheckedBy = t.Union([t.Literal('server'), t.Literal('proxy')]);

/*
 * An API's tools table, replaced whole. Bounds a schema can say are said here; which scopes a row may name, and
 * that names are unique, are the handler's (lib/resources/tools_table.ts), which names the offending row.
 */
const ToolsTableBody = t.Object(
	{
		rows: t.Array(
			t.Object(
				{
					name: t.String({ minLength: 1, maxLength: 128 }),
					scopes: t.Array(t.String())
				},
				{ additionalProperties: false }
			),
			{ maxItems: 200 }
		),
		otherTools: t.Union([t.Literal('refuse'), t.Literal('token')]),
		withoutMethod: t.Union([t.Literal('refuse'), t.Literal('token')]),
		/* Who may call the API at all (specs/124), decided before the table. */
		access: t.Optional(
			t.Object(
				{
					conditions: t.Array(ApiConditionBody, { minItems: 1, maxItems: 4 }),
					timeZone: t.Optional(TimeZoneBody)
				},
				{ additionalProperties: false }
			)
		)
	},
	{ additionalProperties: false }
);

export const CreateResourceBody = t.Object(
	{
		identifier: t.String({ minLength: 1 }),
		name: t.String({ minLength: 1, maxLength: 100 }),
		scopes: t.Array(t.String()),
		scopeDescriptions: t.Optional(ScopeDescriptions),
		tokenFormat: t.Optional(t.Union([t.Literal('jwt'), t.Literal('opaque')])),
		accessTokenTTL: t.Optional(
			t.Number({ minimum: 30, maximum: 86400, multipleOf: 1 })
		),
		trailingSlashSignificant: t.Optional(t.Boolean()),
		checkedBy: t.Optional(CheckedBy)
	},
	/*
	 * Closed on purpose, and not the framework default. TypeBox objects admit unknown keys unless told
	 * otherwise, which would have made a misspelled field a silently discarded value rather than a
	 * refusal — the same failure the clients service guards against by forwarding every accepted key
	 * explicitly.
	 */
	{ additionalProperties: false }
);

/*
 * `identifier` is deliberately absent, and `additionalProperties` stays closed so naming it is a 422
 * rather than a silently ignored field. It is the primary key and the audience of every token already
 * minted for the resource; changing it is a delete and a declare, and saying so is honest where
 * pretending a rename is safe would not be.
 */
export const UpdateResourceBody = t.Object(
	{
		name: t.Optional(t.String({ minLength: 1, maxLength: 100 })),
		scopes: t.Optional(t.Array(t.String())),
		/*
		 * Replaces the whole map. Sent without it, a change to `scopes` drops the descriptions of scopes it
		 * removes and keeps the rest.
		 */
		scopeDescriptions: t.Optional(ScopeDescriptions),
		tokenFormat: t.Optional(t.Union([t.Literal('jwt'), t.Literal('opaque')])),
		accessTokenTTL: t.Optional(
			t.Number({ minimum: 30, maximum: 86400, multipleOf: 1 })
		),
		/*
		 * The application that exchanges the access tokens this API receives for a person's upstream tokens (specs/118
		 * R3), or `null` for none: an MCP server calling GitHub for the agent that called it.
		 */
		exchangedBy: t.Optional(
			t.Union([t.String({ minLength: 1, maxLength: 512 }), t.Null()])
		),
		checkedBy: t.Optional(CheckedBy),
		tools: t.Optional(ToolsTableBody)
	},
	/*
	 * Closed for a sharper reason than the body above: with unknown keys admitted, a caller naming
	 * `identifier` here would get a 200 and no change, having been told nothing. The identifier is the
	 * audience of every token already minted for this resource, so the answer has to be a refusal.
	 */
	{ additionalProperties: false }
);
