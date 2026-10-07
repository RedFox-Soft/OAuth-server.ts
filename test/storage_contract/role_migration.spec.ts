import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import { planRoleMigration, planSuperAdmins } from 'lib/consts/migrations.js';

/**
 * @proves An upgrade turns a bucket's roles into groups without losing anybody's assignment: every declared or
 * held role becomes a group holding exactly its holders, spellings that differ only in case become one group,
 * and nothing is invented for a blank name (spec 071, User Story 4; SC-002).
 */
describe('turning a bucket’s roles into groups', () => {
	it('makes every declared and every held role a group with exactly its holders', () => {
		const plan = planRoleMigration(
			['editor', 'viewer'],
			[
				{ _id: 'u1', roles: ['editor'] },
				{ _id: 'u2', roles: ['editor', 'viewer'] },
				{ _id: 'u3', roles: ['auditor'] }
			]
		);

		expect(plan.groups.map((g) => [g.displayName, g.memberIds])).toEqual([
			['auditor', ['u3']],
			['editor', ['u1', 'u2']],
			['viewer', ['u2']]
		]);
		expect(plan.undeclared).toEqual(['auditor']);
	});

	it('keeps a declared role nobody holds as an empty group', () => {
		const plan = planRoleMigration(['reviewer'], []);

		expect(plan.groups).toEqual([
			{ displayName: 'reviewer', key: 'reviewer', memberIds: [] }
		]);
	});

	it('merges names differing only in case into one group with all their holders, and reports it', () => {
		const plan = planRoleMigration(
			['Editor'],
			[
				{ _id: 'u1', roles: ['editor'] },
				{ _id: 'u2', roles: ['EDITOR'] }
			]
		);

		expect(plan.groups).toEqual([
			{ displayName: 'Editor', key: 'editor', memberIds: ['u1', 'u2'] }
		]);
		expect(plan.merges).toEqual([['EDITOR', 'Editor', 'editor']]);
	});

	it('skips a blank role name and reports it', () => {
		const plan = planRoleMigration(['  '], [{ _id: 'u1', roles: [''] }]);

		expect(plan.groups).toEqual([]);
		expect(plan.skipped).toBe(2);
	});

	it('for every generated set of assignments, maps each (user, role) pair to exactly one membership', () => {
		const name = fc.constantFrom('a', 'A', 'b', 'Beta', 'beta', 'c ', ' c');
		fc.assert(
			fc.property(
				fc.array(name, { maxLength: 4 }),
				fc.array(
					fc.record({
						_id: fc.constantFrom('u1', 'u2', 'u3', 'u4'),
						roles: fc.array(name, { maxLength: 4 })
					}),
					{ maxLength: 6 }
				),
				(declared, raw) => {
					/* One record per user, as a store holds them. */
					const users = [...new Map(raw.map((u) => [u._id, u])).values()];
					const plan = planRoleMigration(declared, users);
					const fold = (n: string) => n.trim().normalize('NFC').toLowerCase();
					const expected = new Set(
						users.flatMap((u) => u.roles.map((r) => `${u._id}|${fold(r)}`))
					);
					const actual = plan.groups.flatMap((g) =>
						g.memberIds.map((id) => `${id}|${g.key}`)
					);
					expect(new Set(actual)).toEqual(expected);
					expect(actual.length).toBe(new Set(actual).size);
				}
			),
			{ numRuns: 300 }
		);
	});
});

/**
 * @proves An upgrade keeps exactly the people who could administer the whole instance able to do so: every
 * holder of `super_admin`, active or not, becomes a member of Super administrators and nobody else does
 * (spec 071, User Story 4 scenario 6; SC-006).
 */
describe('turning super_admin into membership of Super administrators', () => {
	it('makes every holder of super_admin a member, and nobody else', () => {
		const { superAdmins, projectAdmins } = planSuperAdmins([
			{ _id: 'root', roles: ['super_admin', 'project_admin'] },
			{ _id: 'retired', roles: ['super_admin'] },
			{ _id: 'pa', roles: ['project_admin'] },
			{ _id: 'none', roles: [] }
		]);

		expect(superAdmins.sort()).toEqual(['retired', 'root']);
		expect(projectAdmins).toBe(2);
	});
});
