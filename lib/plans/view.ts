import type { UserBucket } from '../adapters/types.js';
import type { Plan } from '../consts/plans.js';
import { catalogue, planOf, plansEnabled } from './catalogue.js';
import { signUpsPaused } from './signups.js';
import { bucketUsage } from './usage.js';

/*
 * A project's plan as the console and an agent read it (specs/102): its limits, what it uses of them, and a warning
 * at 80% and at 100% of each, so nobody meets a limit first as a refusal.
 *
 * Shown to everyone who can read the project while plans are on, and to a super administrator always — they set
 * plans up before turning them on. A tenant sees nothing of plans while they are off.
 */

export interface PlanWarning {
	limit: 'monthlyActiveUsers' | 'applicationsPerProject' | 'apisPerProject';
	level: 'near' | 'reached';
}

export interface PlanView {
	id: string;
	name: string;
	limits: Plan['limits'];
	features: Plan['features'];
	usage: {
		/* Null where the figure is not the caller's to read, or was not counted. */
		monthlyActiveUsers: number | null;
		applications: number;
		apis: number;
	};
	warnings: PlanWarning[];
	signUpsPaused: boolean;
}

export function plansShownTo(caller: { superAdmin: boolean }): boolean {
	return plansEnabled() || caller.superAdmin;
}

const NEAR = 0.8;

function warning(
	limit: PlanWarning['limit'],
	used: number | null,
	max: number | null
): PlanWarning[] {
	if (used === null || max === null) return [];
	if (used >= max) return [{ limit, level: 'reached' }];
	return used >= max * NEAR ? [{ limit, level: 'near' }] : [];
}

export function warningsOf(
	plan: Plan,
	usage: PlanView['usage']
): PlanWarning[] {
	return [
		...warning(
			'monthlyActiveUsers',
			usage.monthlyActiveUsers,
			plan.limits.monthlyActiveUsers
		),
		...warning(
			'applicationsPerProject',
			usage.applications,
			plan.limits.applicationsPerProject
		),
		...warning('apisPerProject', usage.apis, plan.limits.apisPerProject)
	];
}

/* Null for a System project, which carries no plan. */
export async function planViewOf(
	bucket: UserBucket,
	monthlyActiveUsers: number | null
): Promise<PlanView | null> {
	const plan = planOf(bucket, await catalogue());
	if (!plan) return null;
	const counted = await bucketUsage(bucket._id);
	const usage = { monthlyActiveUsers, ...counted };
	return {
		id: plan.id,
		name: plan.name,
		limits: plan.limits,
		features: plan.features,
		usage,
		warnings: warningsOf(plan, usage),
		signUpsPaused: await signUpsPaused(bucket)
	};
}
