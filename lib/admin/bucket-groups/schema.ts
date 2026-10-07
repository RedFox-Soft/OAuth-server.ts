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

export const AssignBucketGroupConnectionBody = t.Object(
	{ connectionId: t.String({ minLength: 1 }) },
	{ additionalProperties: false }
);

/* A page of a group's members: `count` up to 1,000, default 100. Strings, as every query value arrives. */
export const BucketGroupMemberPageQuery = t.Object(
	{
		startIndex: t.Optional(t.String()),
		count: t.Optional(t.String())
	},
	{ additionalProperties: false }
);
