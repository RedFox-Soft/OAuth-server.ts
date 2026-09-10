import { describe, it, expect } from 'bun:test';

import { MIGRATIONS, isNoop, type Migration } from 'lib/consts/migrations.js';

/*
 * The shape of the declared migration set — contract M1.
 *
 * Every rule here is about a mistake that costs nothing to make and cannot be undone once released.
 * A reused id silently marks a new migration as already applied. A missing backend half leaves one
 * datastore quietly unmigrated. An unordered set applies changes in an order nobody chose.
 *
 * The set ships empty, so most of this currently guards an empty array. That is deliberate: the rules
 * have to be in place before the first entry, because the first entry is the one written by somebody
 * who has never seen this file.
 */

function ids(set: readonly Migration[]): string[] {
	return set.map((migration) => migration.id);
}

/**
 * @proves Every declared migration has a unique sortable id, accounts for both backends, and
 * says how it is safe to apply twice and whether it can be reversed.
 */
describe('the declared migration set', () => {
	it('declares no historical migration a PostgreSQL database could never match', () => {
		/*
		 * The one migration this server had is retired rather than carried forward: a historical entry
		 * here would be one no PostgreSQL database can ever satisfy, and it would teach the next author
		 * that such entries belong.
		 *
		 * Stated as the property rather than as `toEqual([])`. An equality on empty is a fact about
		 * today whose only repair, when the first real migration lands, is to delete the case - and
		 * every other rule in this file already holds for a set of any size, including zero.
		 */
		const preLayer = MIGRATIONS.filter(
			(migration) => migration.id < '2026'
		).map((migration) => migration.id);

		expect(preLayer).toEqual([]);
	});

	it('uses each id exactly once', () => {
		// A reused id is recorded as already applied the moment the new migration ships, so its work
		// never runs and nothing reports a problem.
		expect(new Set(ids(MIGRATIONS)).size).toBe(MIGRATIONS.length);
	});

	it('declares ids that sort into their declared order', () => {
		// The array's order is the application order. Keeping the ids sorted too means a reader can tell
		// at a glance whether an entry was inserted in the middle — which is how an ordering assumption
		// gets broken.
		const sorted = [...ids(MIGRATIONS)].sort();
		expect(ids(MIGRATIONS)).toEqual(sorted);
	});

	it('accounts for both backends in every entry', () => {
		const incomplete = MIGRATIONS.filter(
			(migration) =>
				migration.mongodb === undefined || migration.postgres === undefined
		).map((migration) => migration.id);

		expect(incomplete).toEqual([]);
	});

	it('gives every no-op a reason that is not empty', () => {
		// "Not needed here" is not a reason. The field exists so that an absence is a decision somebody
		// wrote down, the same rule the storage inventory applies to an unowned area.
		const unexplained = MIGRATIONS.flatMap((migration) =>
			[migration.mongodb, migration.postgres]
				.filter(isNoop)
				.filter((half) => half.reason.trim().length === 0)
				.map(() => migration.id)
		);

		expect(unexplained).toEqual([]);
	});

	it('says how every entry is safe to apply twice', () => {
		// Required on both backends, because a standalone `mongod` cannot write a migration's effect and
		// its record atomically: a crash between them leaves the effect applied and unrecorded, and the
		// next run applies it again.
		const unstated = MIGRATIONS.filter(
			(migration) => migration.rerunnable.trim().length === 0
		).map((migration) => migration.id);

		expect(unstated).toEqual([]);
	});

	it('states reversibility explicitly on every entry', () => {
		const unstated = MIGRATIONS.filter(
			(migration) => typeof migration.reversible !== 'boolean'
		).map((migration) => migration.id);

		expect(unstated).toEqual([]);
	});

	it('describes every entry', () => {
		// The description is what `db:migrate` prints before applying. An operator deciding whether to
		// run something on production reads this and nothing else.
		const undescribed = MIGRATIONS.filter(
			(migration) => migration.description.trim().length === 0
		).map((migration) => migration.id);

		expect(undescribed).toEqual([]);
	});
});

describe('isNoop', () => {
	it('tells a declared no-op from a step', () => {
		expect(
			isNoop({ noop: true, reason: 'nothing to do on this backend' })
		).toBe(true);
		expect(isNoop({ apply: async () => {} })).toBe(false);
	});
});
