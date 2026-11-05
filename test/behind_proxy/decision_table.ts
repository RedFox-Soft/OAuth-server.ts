import type { Outcome, PathRule, Reason } from 'lib/behind_proxy/decide.ts';

/*
 * The decision table of specs/122 quickstart §2, in one place so the shared decision and the live check are driven
 * by the same rows (C8 through the decision, C14 through the endpoint and the console's inputs).
 *
 * Rules: the root open to Staff, `/admin` to Admins, `/health` public for its exact path. Group ids are passed in
 * because the live check needs the ids of groups that exist in the project.
 */

export type Role = 'none' | 'staff' | 'admins';

export interface DecisionRow {
	person: Role;
	method: string;
	rawPath: string;
	outcome: Outcome;
	reason: Reason;
	rule: string | null;
}

export interface TableGroups {
	staff: string;
	admins: string;
}

export function decisionRules(groups: TableGroups): PathRule[] {
	return [
		{ path: '/', who: { kind: 'groups', groupIds: [groups.staff] } },
		{ path: '/admin', who: { kind: 'groups', groupIds: [groups.admins] } },
		{ path: '/health', who: { kind: 'public', subtree: false } }
	];
}

/* The groups a person of each role is in. */
export function groupsOf(role: Role, groups: TableGroups): string[] | null {
	if (role === 'none') return null;
	return role === 'staff' ? [groups.staff] : [groups.admins];
}

export const DECISION_TABLE: readonly DecisionRow[] = [
	{
		person: 'none',
		method: 'GET',
		rawPath: '/health',
		outcome: 'allow',
		reason: 'public',
		rule: '/health'
	},
	{
		person: 'none',
		method: 'POST',
		rawPath: '/health',
		outcome: 'sign_in',
		reason: 'no_session',
		rule: '/'
	},
	{
		person: 'none',
		method: 'GET',
		rawPath: '/health/x',
		outcome: 'sign_in',
		reason: 'no_session',
		rule: '/'
	},
	{
		person: 'none',
		method: 'GET',
		rawPath: '/HEALTH',
		outcome: 'sign_in',
		reason: 'no_session',
		rule: '/'
	},
	{
		person: 'staff',
		method: 'GET',
		rawPath: '/admin%2e%2e/x',
		outcome: 'deny',
		reason: 'ambiguous_path',
		rule: null
	},
	{
		person: 'staff',
		method: 'GET',
		rawPath: '/Admin/users',
		outcome: 'deny',
		reason: 'not_in_group',
		rule: '/admin'
	},
	{
		person: 'staff',
		method: 'GET',
		rawPath: '/admin/../admin/x',
		outcome: 'deny',
		reason: 'not_in_group',
		rule: '/admin'
	},
	{
		person: 'staff',
		method: 'GET',
		rawPath: '/admin%2Fx',
		outcome: 'deny',
		reason: 'ambiguous_path',
		rule: null
	},
	{
		person: 'admins',
		method: 'GET',
		rawPath: '/admin',
		outcome: 'allow',
		reason: 'allowed',
		rule: '/admin'
	},
	{
		person: 'staff',
		method: 'GET',
		rawPath: '/administrator',
		outcome: 'allow',
		reason: 'allowed',
		rule: '/'
	}
];
