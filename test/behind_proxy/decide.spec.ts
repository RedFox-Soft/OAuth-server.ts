import { describe, expect, it } from 'bun:test';

import {
	decide,
	widenings,
	type Outcome,
	type PathRule,
	type Person
} from 'lib/behind_proxy/decide.ts';
import {
	DECISION_TABLE,
	decisionRules,
	groupsOf,
	type TableGroups
} from './decision_table.ts';

const GROUPS: TableGroups = { staff: 'g-staff', admins: 'g-admins' };
const RULES = decisionRules(GROUPS);

function member(...groupIds: string[]): Person {
	return { canSignIn: true, groupIds };
}

/**
 * @proves Which rule decides a request to an app behind a proxy, and what it decides, cannot be changed by how the
 * path is spelled: the most specific rule wins whatever order the rules were written in, a path the app might read
 * differently is refused outright, a public rule opens no more than its own reads, a deleted group admits nobody,
 * and a change of rules is reported as widening exactly where it lets more people in.
 */
describe('the decision for an app behind a proxy', () => {
	describe('with the root open to Staff, /admin to Admins and /health public', () => {
		it.each(
			DECISION_TABLE.map((row) => [row.method, row.rawPath, row.person, row])
		)(
			'the most specific rule decides %s %s for %s',
			(_method, _path, _person, row) => {
				const groupIds = groupsOf(row.person, GROUPS);

				const decision = decide({
					rules: RULES,
					method: row.method,
					rawPath: row.rawPath,
					person: groupIds ? member(...groupIds) : null
				});

				expect({
					outcome: decision.outcome,
					reason: decision.reason,
					rule: decision.rule
				}).toEqual({
					outcome: row.outcome,
					reason: row.reason,
					rule: row.rule
				});
			}
		);

		it('decides the same whatever order the rules were written in', () => {
			const reversed = [...RULES].reverse();

			const decisions = DECISION_TABLE.map((row) => {
				const groupIds = groupsOf(row.person, GROUPS);
				return decide({
					rules: reversed,
					method: row.method,
					rawPath: row.rawPath,
					person: groupIds ? member(...groupIds) : null
				}).outcome;
			});

			expect(decisions).toEqual(DECISION_TABLE.map((row) => row.outcome));
		});

		it.each([['/Admin/users'], ['/admin/../admin/users'], ['//admin/users']])(
			'a path that differs from /admin only in case, dot segments or doubled slashes is decided by /admin: %s',
			(rawPath) => {
				const decision = decide({
					rules: RULES,
					method: 'GET',
					rawPath,
					person: member(GROUPS.staff)
				});

				expect(decision).toMatchObject({
					outcome: 'deny',
					reason: 'not_in_group',
					rule: '/admin'
				});
			}
		);
	});

	describe('with every path public', () => {
		const open: PathRule[] = [
			{ path: '/', who: { kind: 'public', subtree: true } }
		];

		it.each([
			['an encoded slash', '/admin%2Fusers'],
			['an encoded slash in lower case', '/admin%2fusers'],
			['an encoded backslash', '/admin%5cusers'],
			['a backslash', '/admin\\users'],
			['a semicolon', '/admin;jsessionid=x/users'],
			['a NUL', '/admin\u0000/users'],
			['an encoded NUL', '/admin%00/users'],
			['an encoded dot segment', '/x/%2e%2e/admin'],
			['an encoded dot segment in upper case', '/x/%2E%2E/admin'],
			['a control character', '/admin\u0007'],
			['no leading slash', 'admin/users'],
			['a broken escape', '/admin%zz'],
			['doubled slashes that change what a dot segment removes', '/admin//..']
		])(
			'an ambiguous path is refused without consulting any rule: %s',
			(_what, rawPath) => {
				const decision = decide({
					rules: open,
					method: 'GET',
					rawPath,
					person: member(GROUPS.staff, GROUPS.admins)
				});

				expect(decision).toEqual({
					outcome: 'deny',
					reason: 'ambiguous_path',
					rule: null,
					path: null
				});
			}
		);
	});

	describe('with /health public for its exact path', () => {
		it.each([
			['GET', '/health', 'allow'],
			['HEAD', '/health', 'allow'],
			['POST', '/health', 'sign_in'],
			['DELETE', '/health', 'sign_in'],
			['GET', '/health/details', 'sign_in'],
			['GET', '/Health', 'sign_in']
		] as [string, string, Outcome][])(
			'only GET and HEAD of exactly /health, in that letter case, pass without a session: %s %s',
			(method, rawPath, outcome) => {
				const decision = decide({
					rules: RULES,
					method,
					rawPath,
					person: null
				});

				expect(decision.outcome).toBe(outcome);
			}
		);
	});

	describe('with /docs public together with everything under it', () => {
		const rules: PathRule[] = [
			{ path: '/', who: { kind: 'groups', groupIds: [GROUPS.staff] } },
			{ path: '/docs', who: { kind: 'public', subtree: true } }
		];

		it('a GET under /docs passes without a session', () => {
			const decision = decide({
				rules,
				method: 'GET',
				rawPath: '/docs/guide/intro?lang=en',
				person: null
			});

			expect(decision).toMatchObject({
				outcome: 'allow',
				reason: 'public',
				rule: '/docs'
			});
		});
	});

	describe('with a rule naming a group that has since been deleted', () => {
		const deleted = 'g-deleted';
		const rules: PathRule[] = [
			{ path: '/', who: { kind: 'project' } },
			{ path: '/reports', who: { kind: 'groups', groupIds: [deleted] } }
		];

		it('the deleted group admits no one', () => {
			const decision = decide({
				rules,
				method: 'GET',
				rawPath: '/reports/q3',
				person: member(GROUPS.staff, GROUPS.admins)
			});

			expect(decision).toMatchObject({
				outcome: 'deny',
				reason: 'not_in_group',
				rule: '/reports'
			});
		});
	});

	describe('saved rules, changed', () => {
		it('removing /admin is reported as widening /admin', () => {
			const after = RULES.filter((rule) => rule.path !== '/admin');

			const found = widenings(RULES, after);

			expect(found.map((w) => w.path)).toContain('/admin');
		});

		it('narrowing a rule is reported as no widening', () => {
			const before: PathRule[] = [
				{ path: '/', who: { kind: 'project' } },
				{
					path: '/admin',
					who: { kind: 'groups', groupIds: [GROUPS.staff, GROUPS.admins] }
				}
			];
			const after: PathRule[] = [
				{ path: '/', who: { kind: 'groups', groupIds: [GROUPS.staff] } },
				{ path: '/admin', who: { kind: 'groups', groupIds: [GROUPS.admins] } }
			];

			expect(widenings(before, after)).toEqual([]);
		});
	});
});
