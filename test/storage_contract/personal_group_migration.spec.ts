import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import {
	personalGroupRepairReport,
	planPersonalGroupRepair
} from 'lib/consts/migrations.js';

const member = fc.record({
	userId: fc.string({ minLength: 1, maxLength: 8 }),
	role: fc.constantFrom('owner', 'member')
});

const group = fc.record({
	_id: fc.uuid(),
	kind: fc.constantFrom('personal', 'regular', 'system'),
	members: fc.array(member, { minLength: 1, maxLength: 4 })
});

/* The groups as the migration leaves them: each planned group reduced to the member it keeps. */
function applied(
	groups: readonly { _id: string; kind: string; members: unknown[] }[]
) {
	const plan = planPersonalGroupRepair(groups);
	return groups.map((g) => {
		const repair = plan.find((p) => p.groupId === g._id);
		return repair ? { ...g, members: [repair.keep] } : g;
	});
}

/**
 * @proves An upgrade leaves every personal group with exactly its own administrator, as its owner, touches
 * no other group, finds nothing to do a second time, and reports counts rather than people (spec 075, User
 * Story 3; FR-007, SC-001).
 */
describe('making shared personal groups personal again', () => {
	it('leaves every personal group with only its first member, as owner, and every other group as it was', () => {
		fc.assert(
			fc.property(fc.array(group, { maxLength: 6 }), (groups) => {
				const after = applied(groups);
				groups.forEach((before, i) => {
					const now = after.at(i);
					if (before.kind === 'personal') {
						expect(now?.members).toEqual([
							{ userId: before.members[0]?.userId, role: 'owner' }
						]);
					} else {
						expect(now).toBe(before);
					}
				});
			})
		);
	});

	it('finds nothing to repair in groups it has already repaired', () => {
		fc.assert(
			fc.property(fc.array(group, { maxLength: 6 }), (groups) => {
				expect(planPersonalGroupRepair(applied(groups))).toEqual([]);
			})
		);
	});

	it('counts the groups repaired and the memberships removed, and names no one', () => {
		const plan = planPersonalGroupRepair([
			{
				_id: 'g1',
				kind: 'personal',
				members: [
					{ userId: 'alice', role: 'owner' },
					{ userId: 'bob', role: 'owner' },
					{ userId: 'carol', role: 'member' }
				]
			},
			{
				_id: 'g2',
				kind: 'personal',
				members: [{ userId: 'dave', role: 'owner' }]
			}
		]);

		const report = personalGroupRepairReport(plan);

		expect(report).toEqual([
			'personal groups repaired: 1',
			'memberships removed: 2'
		]);
		expect(report.join(' ')).not.toMatch(/alice|bob|carol|dave/);
	});
});
