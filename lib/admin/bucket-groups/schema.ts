import { t } from 'elysia';

/*
 * Bodies of the bucket-group routes. Their own module, because lib/mcp/catalogue.ts imports schema modules
 * and must never import a route module.
 *
 * `displayName` is trimmed and bounded by the service (1–256 characters after trimming), not here, so the
 * admin API and SCIM refuse the same names with the same rule.
 */
export const CreateBucketGroupBody = t.Object(
	{ displayName: t.String() },
	{ additionalProperties: false }
);

export const RenameBucketGroupBody = t.Object(
	{ displayName: t.String() },
	{ additionalProperties: false }
);

export const AddBucketGroupMembersBody = t.Object(
	{
		userIds: t.Array(t.String({ minLength: 1 }), {
			minItems: 1,
			maxItems: 1000
		})
	},
	{ additionalProperties: false }
);

/*
 * A hand-over is previewed, then confirmed (specs/084 R5): without `confirm` the route answers a 409 preview,
 * and a confirmation carries the `expect` that preview stated, so the consent is to the counts reviewed.
 */
export const AssignBucketGroupConnectionBody = t.Object(
	{
		connectionId: t.String({ minLength: 1 }),
		confirm: t.Optional(t.Boolean()),
		expect: t.Optional(
			t.Object(
				/* Whole numbers by `multipleOf`: `t.Integer` coerces through a string branch an agent would be shown. */
				{
					connectionId: t.String(),
					managed: t.Number({ minimum: 0, multipleOf: 1 }),
					foreign: t.Number({ minimum: 0, multipleOf: 1 })
				},
				{ additionalProperties: false }
			)
		)
	},
	{ additionalProperties: false }
);

/*
 * A page of a group's members: `count` up to 1,000, default 100. Strings, as every query value arrives. `q`
 * narrows it to members whose email or username starts with it, in any letter case, or whose id is exactly it
 * — the users list's own search (specs/089).
 */
export const BucketGroupMemberPageQuery = t.Object(
	{
		startIndex: t.Optional(t.String()),
		count: t.Optional(t.String()),
		q: t.Optional(t.String({ minLength: 1, maxLength: 254 }))
	},
	{ additionalProperties: false }
);
