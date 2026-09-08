import { t } from 'elysia';

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
 * value. Same reasoning as `corsOrigins` in the projects schema: the check runs in the handler so the
 * answer arrives in the admin error shape with something an operator can act on.
 */
export const CreateResourceBody = t.Object(
	{
		identifier: t.String({ minLength: 1 }),
		name: t.String({ minLength: 1, maxLength: 100 }),
		scopes: t.Array(t.String()),
		tokenFormat: t.Optional(t.Union([t.Literal('jwt'), t.Literal('opaque')])),
		accessTokenTTL: t.Optional(
			t.Number({ minimum: 30, maximum: 86400, multipleOf: 1 })
		),
		trailingSlashSignificant: t.Optional(t.Boolean())
	},
	/*
	 * Closed on purpose, and not the framework default. TypeBox objects admit unknown keys unless told
	 * otherwise, which would have made a misspelled field a silently discarded value rather than a
	 * refusal — the same failure the projects route guards against by forwarding every accepted key
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
		tokenFormat: t.Optional(t.Union([t.Literal('jwt'), t.Literal('opaque')])),
		accessTokenTTL: t.Optional(
			t.Number({ minimum: 30, maximum: 86400, multipleOf: 1 })
		)
	},
	/*
	 * Closed for a sharper reason than the body above: with unknown keys admitted, a caller naming
	 * `identifier` here would get a 200 and no change, having been told nothing. The identifier is the
	 * audience of every token already minted for this resource, so the answer has to be a refusal.
	 */
	{ additionalProperties: false }
);
