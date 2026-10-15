import { t } from 'elysia';
import { PLAN_ID_MAX_LENGTH, PLAN_ID_PATTERN } from '../../consts/plans.js';

/*
 * Bodies of the plan routes (specs/102). In a schema module rather than inline, because the MCP catalogue imports
 * these and must never import a route module. Restated with Elysia's own `t` rather than reusing the stored schema
 * in lib/consts/plans.ts: a TypeBox schema built by the other copy of the package does not type-check where Elysia
 * reads a route's body (wiki/concepts/typebox-dual-type-resolution.md). The shapes are the same.
 */
/* A whole number, said as `multipleOf` rather than `t.Integer`, whose format the MCP schema bridge refuses. */
const Limit = t.Union([t.Number({ minimum: 0, multipleOf: 1 }), t.Null()]);

const Limits = {
	monthlyActiveUsers: Limit,
	projectsPerAdministrator: Limit,
	applicationsPerProject: Limit,
	apisPerProject: Limit
};

const Features = {
	enterpriseSignIn: t.Boolean(),
	customSlug: t.Boolean(),
	customDomain: t.Boolean()
};

const PlanId = t.String({
	pattern: PLAN_ID_PATTERN,
	maxLength: PLAN_ID_MAX_LENGTH
});

export const CreatePlanBody = t.Object(
	{
		id: PlanId,
		name: t.String({ minLength: 1, maxLength: 80 }),
		default: t.Boolean(),
		limits: t.Object(Limits, { additionalProperties: false }),
		features: t.Object(Features, { additionalProperties: false })
	},
	{ additionalProperties: false }
);

/*
 * Any of a plan's own fields; each limit and feature on its own, so changing one number does not mean restating the
 * rest. `default: true` makes the plan the default; `false` is refused by the route — a catalogue never has no
 * default, so it changes only by making another plan the default.
 */
export const UpdatePlanBody = t.Object(
	{
		name: t.Optional(t.String({ minLength: 1, maxLength: 80 })),
		default: t.Optional(t.Boolean()),
		limits: t.Optional(
			t.Partial(t.Object(Limits, { additionalProperties: false }))
		),
		features: t.Optional(
			t.Partial(t.Object(Features, { additionalProperties: false }))
		)
	},
	{ additionalProperties: false }
);

export const SetProjectPlanBody = t.Object(
	{ planId: PlanId },
	{ additionalProperties: false }
);
