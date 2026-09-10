import crypto from 'crypto';

import type { Migration } from '../consts/migrations.js';
import type { SchemaMigrationRecord } from '../adapters/types.js';

/*
 * Comparing what a database has had against what this release declares.
 *
 * A pure function of two lists — no clock, no environment, no I/O — because its answer decides
 * whether the server starts, and a comparison entangled with a datastore read could only be tested by
 * standing one up. The startup gate is exactly the code an operator meets when something is already
 * wrong, so it is the last place to want a test that is awkward to run.
 */

export type MigrationStatus = 'current' | 'behind' | 'ahead' | 'diverged';

export interface MigrationComparison {
	readonly status: MigrationStatus;
	/* Declared and not recorded, in declared order — the application order. */
	readonly outstanding: string[];
	/* Recorded and not declared: an older binary against a newer database. */
	readonly unknown: string[];
	/* Recorded under a declaration that has since changed. */
	readonly mismatched: string[];
}

/*
 * A checksum of the declaration a migration was applied from.
 *
 * Covers the declaration's stated identity and not its function bodies. Two closures that do the same
 * thing are different objects and cannot be hashed meaningfully; one reformatted line would then read
 * as an edited migration, and a guard that cries wolf is a guard that gets deleted. What defends the
 * body is review; what this defends is the case review cannot catch by reading a diff — an id already
 * recorded in production being reused for different work.
 */
export function checksumOf(migration: Migration): string {
	const identity = JSON.stringify([
		migration.id,
		migration.description,
		migration.reversible,
		migration.rerunnable
	]);

	return crypto
		.createHash('sha256')
		.update(identity)
		.digest('hex')
		.slice(0, 32);
}

/*
 * The three failures are ranked, and the ranking is the interesting part.
 *
 * `diverged` outranks everything: an id recorded under a declaration that has since changed means the
 * database's own account of itself is no longer trustworthy, so neither of the other answers can be
 * relied on.
 *
 * `ahead` outranks `behind`: a database migrated by a newer release cannot be safely written by this
 * binary at all, whereas being behind is fixed by running a command. When both are true the operator
 * has to deal with `ahead` first, so that is what they are told.
 */
export function compare(
	declared: readonly Migration[],
	records: readonly SchemaMigrationRecord[]
): MigrationComparison {
	const recorded = new Map(records.map((record) => [record.id, record]));
	const declaredIds = new Set(declared.map((migration) => migration.id));

	const outstanding: string[] = [];
	const mismatched: string[] = [];

	for (const migration of declared) {
		const record = recorded.get(migration.id);
		if (record === undefined) {
			outstanding.push(migration.id);
		} else if (record.checksum !== checksumOf(migration)) {
			mismatched.push(migration.id);
		}
	}

	const unknown = records
		.map((record) => record.id)
		.filter((id) => !declaredIds.has(id));

	const status: MigrationStatus =
		mismatched.length > 0
			? 'diverged'
			: unknown.length > 0
				? 'ahead'
				: outstanding.length > 0
					? 'behind'
					: 'current';

	return { status, outstanding, unknown, mismatched };
}
