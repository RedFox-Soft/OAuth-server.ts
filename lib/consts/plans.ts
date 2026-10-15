import { Type as t, type Static } from '@sinclair/typebox';

/*
 * Plans (specs/102): a named set of limits and features a tenant project (stored as a bucket) is on. Declared here,
 * in a leaf module, because the stores, the admin routes, the MCP catalogue and the console all need the shape
 * and none of them may import another's module graph.
 *
 * A numeric limit is `null` for "unlimited". Every limit gates only a new creation: nothing that already exists is
 * switched off, moved or hidden because a plan's numbers are lower than what a project holds.
 */

export const PLAN_ID_PATTERN = '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$';
export const PLAN_ID_MAX_LENGTH = 40;

const Limit = t.Union([t.Integer({ minimum: 0 }), t.Null()]);

export const PlanLimits = t.Object(
	{
		/* A soft cap: reaching it pauses new self-service sign-ups and never refuses a sign-in. */
		monthlyActiveUsers: Limit,
		/* Projects of this plan in the teams one administrator owns. */
		projectsPerAdministrator: Limit,
		/* Applications created by administrators; a dynamically registered one is neither refused nor counted. */
		applicationsPerProject: Limit,
		apisPerProject: Limit
	},
	{ additionalProperties: false }
);
export type PlanLimits = Static<typeof PlanLimits>;

export const PlanFeatures = t.Object(
	{
		/* A generic OpenID Connect provider, or Microsoft bound to one organisation's directory. */
		enterpriseSignIn: t.Boolean(),
		/* Whether the administrator names the slug of a path or subdomain address, or the server generates it. */
		customSlug: t.Boolean(),
		/*
		 * A hostname of the project's own. Recorded for display only: giving a project a hostname is a super
		 * administrator's act today, and super administrators are never limited. The gate belongs to the spec that
		 * opens verified hostnames to tenants.
		 */
		customDomain: t.Boolean()
	},
	{ additionalProperties: false }
);
export type PlanFeatures = Static<typeof PlanFeatures>;

export const Plan = t.Object(
	{
		id: t.String({ pattern: PLAN_ID_PATTERN, maxLength: PLAN_ID_MAX_LENGTH }),
		name: t.String({ minLength: 1, maxLength: 80 }),
		default: t.Boolean(),
		limits: PlanLimits,
		features: PlanFeatures
	},
	{ additionalProperties: false }
);
export type Plan = Static<typeof Plan>;

/* No timestamp of its own: when and by whom the catalogue changed is the audit trail's to say. */
export const PlanCatalogue = t.Object({ plans: t.Array(Plan) });
export type PlanCatalogue = Static<typeof PlanCatalogue>;

export type PlanLimitName =
	| keyof PlanLimits
	| 'regularTeamsPerAdministrator'
	| 'enterpriseSignIn'
	| 'customSlug';

/*
 * What a `plan_limit` refusal names. `plan` is absent for the team allowance, which is an instance setting rather
 * than a plan's; `count` is absent when it would describe another administrator.
 */
export interface PlanLimitDetail {
	readonly name: PlanLimitName;
	readonly plan?: { readonly id: string; readonly name: string };
	readonly count?: number;
	readonly max?: number;
}

export const FREE_PLAN_ID = 'free';

/*
 * The catalogue in force while none is stored. Nothing seeds it: an absent document reads as this, and the first
 * edit stores the whole catalogue, so "seed Free without overwriting what an operator wrote" holds by construction.
 */
export const BUILT_IN_PLANS: readonly Plan[] = [
	{
		id: FREE_PLAN_ID,
		name: 'Free',
		default: true,
		limits: {
			monthlyActiveUsers: 100_000,
			projectsPerAdministrator: 2,
			applicationsPerProject: 10,
			apisPerProject: 10
		},
		features: {
			enterpriseSignIn: false,
			customSlug: false,
			customDomain: false
		}
	}
];
