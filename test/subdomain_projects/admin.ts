import { elysia } from 'lib/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { User } from 'lib/adapters/types.ts';
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

/* An owner of a team of their own, who is not a super administrator. */
export async function teamOwner(): Promise<Caller> {
	const user = await createAdministrator('plain');
	const team = await regularGroup([user]);
	return { user, cookie: await cookieOf(user), teamId: team._id };
}

export async function superAdministrator(): Promise<Caller> {
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

/* A slug no other case in the run holds. */
export function freshSlug(prefix: string): string {
	return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

export async function createProject(
	caller: Caller,
	body: Record<string, unknown>
): Promise<{ status: number; body: unknown }> {
	return call('POST', '/admin/api/projects', caller.cookie, {
		name: 'Project',
		teamId: caller.teamId,
		...body
	});
}

export async function saveAddressForms(
	cookie: string,
	value: 'path' | 'subdomain' | 'both'
): Promise<void> {
	const saved = await call('PUT', '/admin/api/settings', cookie, {
		'projects.addressForms': value
	});
	if (saved.status !== 200) {
		throw new Error(`saving the setting answered ${String(saved.status)}`);
	}
}
