import { ApplicationConfig } from '../configs/application.js';
import { catalogue, defaultOf, plansEnabled } from './catalogue.js';
import { holdingsOf } from './usage.js';

/*
 * What a caller may still create under the plans (specs/102), stated beside their other rights so the console can
 * say so before a form is filled in and an agent before it tries. The routes decide; this only predicts them, for
 * the caller's own allowance — a project created in someone else's team is judged by that team's owners.
 */
export interface PlanRights {
	/* Whether a slug may be named for a new project, or one is generated. */
	nameSlug: boolean;
	/* The caller's projects on the default plan against its per-administrator limit; null when unlimited. */
	projects: {
		count: number;
		max: number;
		plan: { id: string; name: string };
	} | null;
	/* The caller's regular teams against the instance allowance; null when unlimited. */
	teams: { count: number; max: number } | null;
}

const UNLIMITED: PlanRights = { nameSlug: true, projects: null, teams: null };

export async function planRightsOf(caller: {
	superAdmin: boolean;
	userId: string;
}): Promise<PlanRights> {
	if (!plansEnabled() || caller.superAdmin) return UNLIMITED;
	const plans = await catalogue();
	const plan = defaultOf(plans);
	const holdings = await holdingsOf(caller.userId, plans);
	const max = plan.limits.projectsPerAdministrator;
	return {
		nameSlug: plan.features.customSlug,
		projects:
			max === null
				? null
				: {
						count: holdings.projects.get(plan.id) ?? 0,
						max,
						plan: { id: plan.id, name: plan.name }
					},
		teams: {
			count: holdings.regularTeams,
			max: ApplicationConfig['plans.regularTeamsPerAdministrator']
		}
	};
}
