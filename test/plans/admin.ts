import { elysia } from 'lib/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { getPlanCatalogueStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { BUILT_IN_PLANS, type Plan } from 'lib/consts/plans.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { regularGroup } from '../admin/ownership_fixtures.ts';

/* An administrator of the console, as the console's own requests carry them. */
export interface Caller {
	user: User;
	cookie: string;
	teamId: string;
}

export async function cookieOf(user: User): Promise<string> {
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

/* An owner of a regular team of their own, who is not a super administrator. */
export async function tenant(): Promise<Caller> {
	const user = await createAdministrator('plain');
	const team = await regularGroup([user]);
	return { user, cookie: await cookieOf(user), teamId: team._id };
}

export async function superAdmin(): Promise<Caller> {
	const user = await createAdministrator('super');
	const team = await regularGroup([user]);
	return { user, cookie: await cookieOf(user), teamId: team._id };
}

export async function call(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			redirect: 'manual',
			headers: { 'content-type': 'application/json', cookie },
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text.startsWith('{') || text.startsWith('[') ? JSON.parse(text) : text
	};
}

/* Switches plan enforcement through the settings route, as an operator does. */
export async function withPlans(operator: Caller, on: boolean): Promise<void> {
	const saved = await call('PUT', '/admin/api/settings', operator.cookie, {
		'plans.enabled': on
	});
	if (saved.status !== 200) {
		throw new Error(`saving plans.enabled answered ${String(saved.status)}`);
	}
}

/* A slug no other case in the run holds. */
export function freshSlug(prefix: string): string {
	return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

export function createProject(
	caller: Caller,
	body: Record<string, unknown> = {}
): Promise<{ status: number; body: unknown }> {
	return call('POST', '/admin/api/projects', caller.cookie, {
		name: 'Project',
		teamId: caller.teamId,
		...body
	});
}

/* The project's id, from a creation that must have succeeded. */
export function idOf(created: { status: number; body: unknown }): string {
	if (created.status !== 201) {
		throw new Error(
			`creating the project answered ${String(created.status)}: ${JSON.stringify(created.body)}`
		);
	}
	return (created.body as { _id: string })._id;
}

/* The built-in Free plan with some of its numbers changed, stored as the whole catalogue. */
export async function storeFree(
	limits: Partial<Plan['limits']> = {},
	features: Partial<Plan['features']> = {}
): Promise<void> {
	const [free] = BUILT_IN_PLANS;
	await getPlanCatalogueStore().set({
		plans: [
			{
				...free,
				limits: { ...free.limits, ...limits },
				features: { ...free.features, ...features }
			}
		]
	});
}

export async function storeCatalogue(plans: Plan[]): Promise<void> {
	await getPlanCatalogueStore().set({ plans });
}

/* The 409 a plan answers, as the admin plane shapes it. */
export interface PlanRefusal {
	error: 'admin_error';
	message: string;
	code: 'plan_limit';
	limit: {
		name: string;
		plan?: { id: string; name: string };
		count?: number;
		max?: number;
	};
}

export function refusalOf(answer: {
	status: number;
	body: unknown;
}): PlanRefusal {
	if (answer.status !== 409) {
		throw new Error(
			`expected a plan refusal, got ${String(answer.status)}: ${JSON.stringify(answer.body)}`
		);
	}
	return answer.body as PlanRefusal;
}
