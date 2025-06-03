import { t, type Static } from 'elysia';

export const ClientSchema = t.Object(
	{
		subjectType: t.Union([t.Literal('pairwise'), t.Literal('public')]),
		'authorization.requirePushedAuthorizationRequests': t.Boolean()
	},
	{ additionalProperties: false }
);

export type ClientSchemaType = Static<typeof ClientSchema>;
