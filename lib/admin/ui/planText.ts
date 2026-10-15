import type { Plan } from '../../consts/plans.js';
import type { PlanView, PlanWarning } from '../../plans/view.js';

export type { PlanView, PlanWarning };

/*
 * How a plan reads on every screen that shows one (specs/102): the catalogue card, a project's Plan card and the
 * Usage page. One table, so a limit is called the same thing wherever an operator meets it.
 */

export type PlanLimitKey = keyof Plan['limits'];
export type PlanFeatureKey = keyof Plan['features'];

export const LIMIT_LABEL: Record<PlanLimitKey, string> = {
	monthlyActiveUsers: 'Monthly active users',
	projectsPerAdministrator: 'Projects per administrator',
	applicationsPerProject: 'Applications per project',
	apisPerProject: 'APIs per project'
};

export const LIMIT_ORDER: readonly PlanLimitKey[] = [
	'monthlyActiveUsers',
	'projectsPerAdministrator',
	'applicationsPerProject',
	'apisPerProject'
];

export const FEATURE_LABEL: Record<PlanFeatureKey, string> = {
	enterpriseSignIn: 'Enterprise sign-in',
	customSlug: 'Custom address name',
	customDomain: 'Custom domain'
};

export const FEATURE_ORDER: readonly PlanFeatureKey[] = [
	'enterpriseSignIn',
	'customSlug',
	'customDomain'
];

// A fixed locale: the page is rendered on the server and hydrated, and both must print the same digits.
export function countText(n: number): string {
	return n.toLocaleString('en-US');
}

export function limitText(max: number | null): string {
	return max === null ? 'Unlimited' : countText(max);
}

const SUBJECT: Record<PlanWarning['limit'], string> = {
	monthlyActiveUsers: 'Active users',
	applicationsPerProject: 'Applications',
	apisPerProject: 'APIs'
};

/* A short label for a table cell. */
export function warningTag(warning: PlanWarning): string {
	if (warning.level === 'near')
		return `${SUBJECT[warning.limit]}: close to the limit`;
	return warning.limit === 'monthlyActiveUsers'
		? 'Active users: sign-ups paused'
		: `${SUBJECT[warning.limit]}: limit reached`;
}

/*
 * The sentence on a project's Plan card. Active users are a soft cap: reaching it pauses new sign-ups only, and
 * that is said in the same breath, because "limit reached" alone reads as people being shut out.
 */
export function warningSentence(
	warning: PlanWarning,
	plan: Pick<PlanView, 'name' | 'signUpsPaused'>
): string {
	if (warning.limit === 'monthlyActiveUsers') {
		if (warning.level === 'near') {
			return `Close to the ${plan.name} plan's monthly active users. At the limit, new sign-ups pause; people who already have an account still sign in.`;
		}
		return plan.signUpsPaused
			? 'Sign-ups are paused: people who already have an account still sign in.'
			: `This project has reached the ${plan.name} plan's monthly active users.`;
	}
	const what =
		warning.limit === 'applicationsPerProject' ? 'applications' : 'APIs';
	return warning.level === 'near'
		? `Close to the ${plan.name} plan's limit on ${what}.`
		: `The ${plan.name} plan's limit on ${what} is reached: no more can be added.`;
}

/*
 * Why a project's Applications or APIs tab cannot add one, or null when it can: the same sentence the server's
 * refusal gives. Only a plan the caller is held to is passed in: a super administrator is never limited.
 */
export function atLimit(
	plan: PlanView | null | undefined,
	kind: 'applications' | 'apis'
): string | null {
	if (!plan) return null;
	const max =
		plan.limits[
			kind === 'applications' ? 'applicationsPerProject' : 'apisPerProject'
		];
	if (max === null || plan.usage[kind] < max) return null;
	const one = kind === 'applications' ? 'application' : 'API';
	const many = kind === 'applications' ? 'applications' : 'APIs';
	return `This project is on the ${plan.name} plan, which allows ${countText(max)} ${max === 1 ? one : many}. Ask for a larger plan to add more.`;
}
