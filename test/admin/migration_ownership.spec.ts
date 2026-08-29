import { describe, it, expect } from 'bun:test';
import {
	planOwnershipMigration,
	reachAfter,
	type LegacyContainer
} from 'lib/admin/groups/migration.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * FR-038: every project and bucket that exists when this feature ships must end up owned by a group,
 * and every administrator who can reach one today must still reach it afterwards — no more, no fewer.
 *
 * Asserted as that property rather than by checking the plan against a restatement of its own rules.
 * `reachBefore` is computed straight from the legacy `managedBy` list, which is what "who can reach it
 * today" actually meant, so the two sides of the comparison are derived independently.
 */

const personal = new Map([
	['alice', 'g-alice'],
	['bob', 'g-bob'],
	['carol', 'g-carol']
]);

function reachBefore(container: LegacyContainer): Set<string> {
	return new Set(container.managedBy);
}

function assertAccessPreserved(containers: LegacyContainer[]) {
	const plan = planOwnershipMigration(containers, personal);
	for (const container of containers) {
		expect(
			[...reachAfter(plan, container._id, personal)].sort(),
			`access changed for ${container._id}`
		).toEqual([...reachBefore(container)].sort());
	}
	return plan;
}

describe('ownership migration', () => {
	it('sends a single-manager container to that administrator’s personal group', () => {
		const plan = assertAccessPreserved([
			{ _id: 'p1', managedBy: ['alice'] },
			{ _id: 'p2', managedBy: ['bob'] }
		]);

		expect(plan.assignments.get('p1')).toBe('g-alice');
		expect(plan.assignments.get('p2')).toBe('g-bob');
		expect(plan.groupsToCreate).toHaveLength(0);
	});

	it('sends an unmanaged container to the reserved holding group', () => {
		const plan = planOwnershipMigration(
			[{ _id: 'p1', managedBy: [] }],
			personal
		);

		expect(plan.assignments.get('p1')).toBe(UNASSIGNED_GROUP_ID);
		// Reachable by super administrators and nobody else — exactly who could reach it before.
		expect(reachAfter(plan, 'p1', personal).size).toBe(0);
	});

	it('gives one generated group to containers with identical manager sets', () => {
		const plan = assertAccessPreserved([
			{ _id: 'p1', managedBy: ['alice', 'bob'] },
			{ _id: 'p2', managedBy: ['bob', 'alice'] }
		]);

		expect(plan.groupsToCreate).toHaveLength(1);
		expect(plan.assignments.get('p1')).toBe(plan.assignments.get('p2'));
		expect(plan.groupsToCreate[0]!.needsReview).toBe(true);
		expect(plan.groupsToCreate[0]!.members.map((m) => m.userId).sort()).toEqual(
			['alice', 'bob']
		);
	});

	/*
	 * The failure this whole rule exists to prevent, and the one the spec called out by name: {A,B} and
	 * {A,C} share a manager but are not the same tenant. Merging them would hand B access to C's
	 * containers, and the result would look like an ordinary group afterwards.
	 */
	it('never merges two tenants that merely share a manager', () => {
		const plan = assertAccessPreserved([
			{ _id: 'p1', managedBy: ['alice', 'bob'] },
			{ _id: 'p2', managedBy: ['alice', 'carol'] }
		]);

		expect(plan.groupsToCreate).toHaveLength(2);
		expect(plan.assignments.get('p1')).not.toBe(plan.assignments.get('p2'));
		expect(reachAfter(plan, 'p1', personal).has('carol')).toBe(false);
		expect(reachAfter(plan, 'p2', personal).has('bob')).toBe(false);
	});

	it('treats a duplicated manager as the same tenant as one naming them once', () => {
		const plan = assertAccessPreserved([
			{ _id: 'p1', managedBy: ['alice', 'alice'] },
			{ _id: 'p2', managedBy: ['alice'] }
		]);

		expect(plan.assignments.get('p1')).toBe('g-alice');
		expect(plan.assignments.get('p2')).toBe('g-alice');
	});

	it('holds a container whose only manager no longer has an account', () => {
		const plan = planOwnershipMigration(
			[{ _id: 'p1', managedBy: ['deleted-admin'] }],
			personal
		);

		// Not a group invented for somebody who is not there, which nobody could reach anyway.
		expect(plan.assignments.get('p1')).toBe(UNASSIGNED_GROUP_ID);
	});

	it('preserves access across a mixed estate', () => {
		assertAccessPreserved([
			{ _id: 'a', managedBy: [] },
			{ _id: 'b', managedBy: ['alice'] },
			{ _id: 'c', managedBy: ['alice', 'bob'] },
			{ _id: 'd', managedBy: ['bob', 'alice'] },
			{ _id: 'e', managedBy: ['alice', 'carol'] },
			{ _id: 'f', managedBy: ['carol'] }
		]);
	});
});
