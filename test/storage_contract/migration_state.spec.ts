import { describe, it, expect } from 'bun:test';

import type { Migration } from 'lib/consts/migrations.js';
import { compare, checksumOf } from 'lib/migrations/state.js';
import type { SchemaMigrationRecord } from 'lib/adapters/types.js';

/*
 * Applied versus declared, as a pure function of two lists — contract M4.
 *
 * Pure because the answer decides whether a server starts. A comparison entangled with a datastore
 * read could only be tested by standing one up, and the startup gate is precisely the code an
 * operator meets when something is already wrong.
 *
 * `ahead` is the row worth reading twice. It means an older binary is pointed at a database a newer
 * release migrated, and the failure of getting it wrong is not a refusal-that-should-have-passed but
 * a server happily writing records in a shape the newer code will misread.
 */

function migration(id: string, extra: Partial<Migration> = {}): Migration {
	return {
		id,
		description: `the ${id} migration`,
		reversible: true,
		rerunnable: 'idempotent by construction in this fixture',
		mongodb: { noop: true, reason: 'fixture' },
		postgres: { noop: true, reason: 'fixture' },
		...extra
	};
}

function applied(entry: Migration): SchemaMigrationRecord {
	return {
		id: entry.id,
		appliedAt: new Date('2026-01-01T00:00:00.000Z'),
		checksum: checksumOf(entry)
	};
}

describe('compare', () => {
	const first = migration('0001-first');
	const second = migration('0002-second');

	it('reports a database holding every declared migration as current', () => {
		expect(compare([first, second], [applied(first), applied(second)])).toEqual(
			{
				status: 'current',
				outstanding: [],
				unknown: [],
				mismatched: []
			}
		);
	});

	it('reports an empty database with no declarations as current', () => {
		// A release that declares nothing cannot be behind, and a fresh install of it must start.
		expect(compare([], [])).toEqual({
			status: 'current',
			outstanding: [],
			unknown: [],
			mismatched: []
		});
	});

	it('reports a database missing a declared migration as behind', () => {
		expect(compare([first, second], [applied(first)])).toEqual({
			status: 'behind',
			outstanding: ['0002-second'],
			unknown: [],
			mismatched: []
		});
	});

	it('lists outstanding migrations in declared order, not record order', () => {
		const third = migration('0003-third');
		const result = compare([first, second, third], []);
		expect(result.outstanding).toEqual([
			'0001-first',
			'0002-second',
			'0003-third'
		]);
	});

	it('reports a record this release does not declare as ahead', () => {
		// An older binary against a database a newer release migrated.
		expect(compare([first], [applied(first), applied(second)])).toEqual({
			status: 'ahead',
			outstanding: [],
			unknown: ['0002-second'],
			mismatched: []
		});
	});

	it('prefers ahead over behind when both are true', () => {
		// Being ahead means this binary cannot safely write at all, so it is the more serious of the
		// two and the one the operator has to act on first.
		const result = compare(
			[first, second],
			[applied(second), applied(migration('0009-future'))]
		);
		expect(result.status).toBe('ahead');
		expect(result.unknown).toEqual(['0009-future']);
		expect(result.outstanding).toEqual(['0001-first']);
	});

	it('reports a released migration edited after the fact as diverged', () => {
		// Same id, different declaration: a different migration wearing an id that is already recorded.
		// Present-or-absent cannot see this, which is the whole reason a checksum is stored.
		const edited = migration('0001-first', { description: 'quietly changed' });
		expect(compare([edited], [applied(first)])).toEqual({
			status: 'diverged',
			outstanding: [],
			unknown: [],
			mismatched: ['0001-first']
		});
	});

	it('prefers diverged over every other status', () => {
		const edited = migration('0001-first', { description: 'quietly changed' });
		expect(compare([edited, second], [applied(first)]).status).toBe('diverged');
	});

	it('is a pure function of its two arguments', () => {
		const declared = [first, second];
		const records = [applied(first)];
		const once = compare(declared, records);
		const twice = compare(declared, records);

		expect(once).toEqual(twice);
		// Neither input is mutated — the gate runs on every start and a comparison that consumed its
		// arguments would answer differently the second time.
		expect(declared).toHaveLength(2);
		expect(records).toHaveLength(1);
	});
});

describe('checksumOf', () => {
	it('is stable for one declaration', () => {
		const entry = migration('0001-first');
		expect(checksumOf(entry)).toBe(checksumOf(migration('0001-first')));
	});

	it('changes when the declaration changes', () => {
		expect(checksumOf(migration('0001-first'))).not.toBe(
			checksumOf(migration('0001-first', { description: 'other' }))
		);
		expect(checksumOf(migration('0001-first'))).not.toBe(
			checksumOf(migration('0001-first', { reversible: false }))
		);
	});

	it('ignores which backend halves are steps rather than no-ops', () => {
		// A function body cannot be hashed meaningfully — two closures that do the same thing are
		// different objects, and one reformatted line would read as an edited migration. What the
		// checksum covers is the declaration's stated identity, and the guard against a changed body is
		// review, not arithmetic.
		const withStep = migration('0001-first', {
			postgres: { apply: async () => {} }
		});
		expect(checksumOf(withStep)).toBe(checksumOf(migration('0001-first')));
	});
});
