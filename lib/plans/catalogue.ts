import { getPlanCatalogueStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { ApplicationConfig } from '../configs/application.js';
import { BUILT_IN_PLANS, type Plan } from '../consts/plans.js';
import { UNASSIGNED_GROUP_ID } from '../admin/consts.js';

/*
 * Plans (specs/102). The catalogue, which plan a bucket is on, and whether any of it is enforced. Read per call,
 * never cached: the catalogue is one small document, and a super administrator's edit must hold at the next check
 * on every process rather than at each process's next cache expiry.
 */

export function plansEnabled(): boolean {
	return ApplicationConfig['plans.enabled'];
}

/* The stored catalogue, or the built-in one while nothing is stored. */
export async function catalogue(): Promise<readonly Plan[]> {
	return (await getPlanCatalogueStore().get())?.plans ?? BUILT_IN_PLANS;
}

/* The plan a new bucket is put on. The routes keep exactly one; the first plan stands in only if that is broken. */
export function defaultOf(plans: readonly Plan[]): Plan {
	return plans.find((plan) => plan.default) ?? plans.at(0) ?? BUILT_IN_PLANS[0];
}

export async function defaultPlan(): Promise<Plan> {
	return defaultOf(await catalogue());
}

/*
 * The plan a bucket is on, or null for a bucket of the System group, which carries none and is never limited.
 *
 * A bucket outside the System group always records its plan (lib/adapters/types.ts, `planId`), and a plan cannot
 * be deleted while one names it. The fallback to the default is a guard against a defect in either, and it falls
 * towards a limit, never towards none: a bucket that lost its plan is treated as a new one would be.
 */
export function planOf(
	bucket: Pick<UserBucket, 'ownerGroupId' | 'planId'>,
	plans: readonly Plan[]
): Plan | null {
	if (bucket.ownerGroupId === UNASSIGNED_GROUP_ID) return null;
	return plans.find((plan) => plan.id === bucket.planId) ?? defaultOf(plans);
}
