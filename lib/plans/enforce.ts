import type { Group, UserBucket } from '../adapters/types.js';
import { getBucketStore } from '../adapters/index.js';
import { ApplicationConfig } from '../configs/application.js';
import type { Plan, PlanLimitDetail } from '../consts/plans.js';
import { AdminError } from '../admin/auth/rbac.js';
import { isSuperAdmin } from '../admin/super_admins.js';
import { catalogue, defaultOf, planOf, plansEnabled } from './catalogue.js';
import { classifyProvider, type ProviderInput } from './provider.js';
import {
	bucketUsage,
	holdingsOf,
	liveBuckets,
	ownsGroup,
	type Holdings
} from './usage.js';

/*
 * The plan checks (specs/102). Each is called by an admin route after its authorization and before its audit write,
 * so a refused request leaves no audit entry and no write, and the console and an agent — which dispatches into the
 * same routes — are limited alike. Never called from a store: a store has no caller to exempt and runs after the
 * audit.
 *
 * Every check is a no-op while plans are off and for a super administrator, and gates only a new creation: nothing
 * that already exists is refused, switched off or moved because a plan allows less than it holds.
 *
 * Count, then create — without a lock. Two creations racing at one below a limit may both succeed and leave a
 * project one over. Accepted: the limit is commercial and soft, the project keeps working, and the next creation is
 * refused; preventing it would need a transaction around every creation on both backends.
 */

interface Caller {
	readonly superAdmin: boolean;
	readonly userId?: string;
}

function exempt(caller: Caller): boolean {
	return !plansEnabled() || caller.superAdmin;
}

function refuse(message: string, limit: PlanLimitDetail): never {
	throw new AdminError(409, message, { code: 'plan_limit', limit });
}

function named(plan: Plan): { id: string; name: string } {
	return { id: plan.id, name: plan.name };
}

function plural(count: number, one: string, many: string): string {
	return `${String(count)} ${count === 1 ? one : many}`;
}

/* A per-project count against its limit; `null` is unlimited. */
async function assertRoomFor(
	caller: Caller,
	bucket: UserBucket,
	kind: 'applications' | 'apis'
): Promise<void> {
	if (exempt(caller)) return;
	const plan = planOf(bucket, await catalogue());
	if (!plan) return;
	const name =
		kind === 'applications' ? 'applicationsPerProject' : 'apisPerProject';
	const max = plan.limits[name];
	if (max === null) return;
	const count = (await bucketUsage(bucket._id))[kind];
	if (count < max) return;
	refuse(
		`This project is on the ${plan.name} plan, which allows ${plural(max, kind === 'applications' ? 'application' : 'API', kind === 'applications' ? 'applications' : 'APIs')}. Ask for a larger plan to add more.`,
		{ name, plan: named(plan), count, max }
	);
}

export function assertApplicationRoom(
	caller: Caller,
	bucket: UserBucket
): Promise<void> {
	return assertRoomFor(caller, bucket, 'applications');
}

export function assertApiRoom(
	caller: Caller,
	bucket: UserBucket
): Promise<void> {
	return assertRoomFor(caller, bucket, 'apis');
}

export async function assertSocialSignIn(
	caller: Caller,
	bucket: UserBucket,
	provider: ProviderInput
): Promise<void> {
	if (exempt(caller)) return;
	const plan = planOf(bucket, await catalogue());
	if (!plan || plan.features.enterpriseSignIn) return;
	if (classifyProvider(provider) === 'social') return;
	refuse(
		`This project is on the ${plan.name} plan, which offers sign-in with Google, Apple, GitHub and Microsoft for every account. A generic OpenID Connect provider, or Microsoft for one organisation, needs a larger plan.`,
		{ name: 'enterpriseSignIn', plan: named(plan) }
	);
}

/*
 * Whether the caller may name a slug for a project on `plan` — the default plan for a new project, the project's own
 * for an address change. True when it is exempt, or the plan includes a custom slug.
 */
export function mayNameSlug(caller: Caller, plan: Plan | null): boolean {
	return exempt(caller) || plan === null || plan.features.customSlug;
}

export function refuseNamedSlug(plan: Plan): never {
	refuse(
		`Projects on the ${plan.name} plan are given a generated address name; choosing your own needs a larger plan. Leave the name out and one is generated.`,
		{ name: 'customSlug', plan: named(plan) }
	);
}

export async function newProjectPlan(): Promise<Plan> {
	return defaultOf(await catalogue());
}

/*
 * Whether `userId`, owning `holdings`, may own `incoming` more projects of `plan` on top. `self` decides whether
 * the refusal may say their numbers: only the caller's own are the caller's to read.
 */
function assertOwnerRoom(
	plan: Plan,
	holdings: Holdings,
	incoming: number,
	self: boolean
): void {
	const max = plan.limits.projectsPerAdministrator;
	if (max === null || incoming === 0) return;
	const count = holdings.projects.get(plan.id) ?? 0;
	if (count + incoming <= max) return;
	if (self) {
		refuse(
			`You own ${plural(count, 'project', 'projects')} on the ${plan.name} plan, which allows ${String(max)} per administrator.`,
			{ name: 'projectsPerAdministrator', plan: named(plan), count, max }
		);
	}
	refuse(
		`An owner of that team already owns as many projects on the ${plan.name} plan as it allows.`,
		{ name: 'projectsPerAdministrator', plan: named(plan), max }
	);
}

/*
 * A project arriving in `group` — created there, moved there, or restored there — counted against every owner of
 * the group. An owner who is a super administrator is not limited. The arriving bucket is left out of each owner's
 * existing holdings, so a move between two teams of the same owner changes nothing.
 */
export async function assertProjectRoom(
	caller: Caller,
	group: Group,
	incoming: Pick<UserBucket, 'ownerGroupId' | 'planId'> & { _id?: string }
): Promise<void> {
	if (exempt(caller)) return;
	const plans = await catalogue();
	const plan = planOf({ ...incoming, ownerGroupId: group._id }, plans);
	if (!plan) return;
	const excluding = new Set(incoming._id === undefined ? [] : [incoming._id]);
	for (const member of group.members) {
		if (member.role !== 'owner' || (await isSuperAdmin(member.userId))) {
			continue;
		}
		assertOwnerRoom(
			plan,
			await holdingsOf(member.userId, plans, excluding),
			1,
			member.userId === caller.userId
		);
	}
}

function teamAllowance(): number {
	return ApplicationConfig['plans.regularTeamsPerAdministrator'];
}

function refuseTeams(count: number, self: boolean): never {
	const max = teamAllowance();
	refuse(
		self
			? `You own ${plural(count, 'team', 'teams')}; an administrator may own ${String(max)} besides their personal team.`
			: `That administrator already owns as many teams as an administrator may.`,
		self
			? { name: 'regularTeamsPerAdministrator', count, max }
			: { name: 'regularTeamsPerAdministrator', max }
	);
}

/* A new regular team, owned by the caller. A new team holds no project, so only the team allowance applies. */
export async function assertTeamRoom(
	caller: Caller & { userId: string }
): Promise<void> {
	if (exempt(caller)) return;
	const holdings = await holdingsOf(caller.userId, await catalogue());
	if (holdings.regularTeams + 1 > teamAllowance()) {
		refuseTeams(holdings.regularTeams, true);
	}
}

/*
 * `userId` becoming an owner of `group` — added as one, promoted to one, or accepting an invitation as one. They
 * take on the team (if regular) and every live project in it. `userId` is undefined for an invitation accepted by a
 * new account, which owns nothing yet.
 */
export async function assertMayBecomeOwner(
	caller: Caller,
	userId: string | undefined,
	group: Group
): Promise<void> {
	if (exempt(caller)) return;
	if (userId !== undefined && (await isSuperAdmin(userId))) return;
	if (userId !== undefined && ownsGroup(group, userId)) return;
	const plans = await catalogue();
	const holdings: Holdings =
		userId === undefined
			? { projects: new Map(), regularTeams: 0 }
			: await holdingsOf(userId, plans);
	const self = userId !== undefined && userId === caller.userId;
	if (group.kind === 'regular' && holdings.regularTeams + 1 > teamAllowance()) {
		refuseTeams(holdings.regularTeams, self);
	}
	const incoming = new Map<string, { plan: Plan; count: number }>();
	for (const bucket of liveBuckets(
		await getBucketStore().listByGroup(group._id)
	)) {
		const plan = planOf(bucket, plans);
		if (!plan) continue;
		const seen = incoming.get(plan.id);
		incoming.set(plan.id, { plan, count: (seen?.count ?? 0) + 1 });
	}
	for (const { plan, count } of incoming.values()) {
		assertOwnerRoom(plan, holdings, count, self);
	}
}
