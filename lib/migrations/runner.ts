import {
	isNoop,
	type Migration,
	type MigrationStep
} from '../consts/migrations.js';
import type { SchemaMigrationRecord } from '../adapters/types.js';
import { checksumOf, compare, type MigrationComparison } from './state.js';

/*
 * Applying outstanding migrations.
 *
 * The declared set arrives as an ARGUMENT rather than being imported, and that is what makes the
 * machinery testable at all: the real set ships empty, so without injection there would be nothing to
 * run and the runner would be covered only by whichever migration happened to be written first. The
 * same shape `validateConfiguration` uses to check a candidate configuration with production rules.
 *
 * The backend arrives the same way. Nothing here knows what a datastore is; it knows how to read the
 * applied set, how to write one record, how to hold a lock, and which half of a declaration to run.
 */

export interface MigrationBackend {
	/* Which half of each declaration this backend runs. */
	readonly name: 'mongodb' | 'postgres';
	/* Passed to a step's `apply`. Opaque here on purpose — a driver type would be knowledge this
	 * module has no use for. */
	readonly handle: unknown;
	readAll(): Promise<SchemaMigrationRecord[]>;
	write(entry: SchemaMigrationRecord): Promise<void>;
	/*
	 * Holds mutual exclusion for the whole run. Required rather than optional, so a backend cannot be
	 * wired in without deciding how two concurrent runs are kept apart — the failure it prevents is two
	 * servers starting at once and applying one migration twice.
	 */
	withLock<T>(run: () => Promise<T>): Promise<T>;
}

export interface RunResult {
	/* Applied and recorded, in the order they ran. */
	readonly applied: string[];
	/* Declared as a no-op for this backend: recorded as applied, with no effect performed. */
	readonly skipped: string[];
	readonly status: MigrationComparison['status'];
}

function halfFor(migration: Migration, backend: MigrationBackend) {
	return backend.name === 'postgres' ? migration.postgres : migration.mongodb;
}

/* What a run would do, without doing any of it. */
export async function plan(
	declared: readonly Migration[],
	backend: MigrationBackend
): Promise<MigrationComparison> {
	return compare(declared, await backend.readAll());
}

/*
 * Applies every outstanding migration, in declared order, under the backend's lock.
 *
 * Stops at the first failure, leaving everything already applied recorded — so a re-run resumes rather
 * than restarts. That is not merely convenient: re-running a step is safe by contract (every
 * declaration says how), but re-running the whole set would multiply that risk by the number of steps
 * that had already succeeded.
 *
 * A no-op half is recorded as applied without performing anything. Skipping the record instead would
 * leave that backend reporting itself behind forever, on a migration it will never have work for.
 */
export async function run(
	declared: readonly Migration[],
	backend: MigrationBackend
): Promise<RunResult> {
	return backend.withLock(async () => {
		const state = compare(declared, await backend.readAll());

		/*
		 * Refused, not repaired. `ahead` means an older binary against a newer database and `diverged`
		 * means the database's account of itself cannot be trusted; applying anything in either state
		 * would be writing on top of a disagreement rather than resolving it.
		 */
		if (state.status === 'ahead' || state.status === 'diverged') {
			return { applied: [], skipped: [], status: state.status };
		}

		const outstanding = new Set(state.outstanding);
		const applied: string[] = [];
		const skipped: string[] = [];

		for (const migration of declared) {
			if (!outstanding.has(migration.id)) continue;

			const half = halfFor(migration, backend);
			if (isNoop(half)) {
				skipped.push(migration.id);
			} else {
				await (half as MigrationStep).apply(backend.handle);
				applied.push(migration.id);
			}

			await backend.write({
				id: migration.id,
				appliedAt: new Date(),
				checksum: checksumOf(migration)
			});
		}

		return { applied, skipped, status: 'current' };
	});
}

/*
 * Marks every declared migration as applied without performing any of them.
 *
 * For a database being provisioned from empty, which is at the current shape by construction — the
 * provisioning routine builds what the current release declares, so replaying the history that led
 * there would at best do nothing and at worst rewrite data the release never had.
 *
 * Deliberately NOT the same as "the records table is empty". A real deployment that predates the first
 * migration also has no records, and baselining it would skip work it genuinely needs. Only the caller
 * knows which case it is in, which is why this is a separate function and not a branch inside `run`.
 */
export async function baseline(
	declared: readonly Migration[],
	backend: MigrationBackend
): Promise<string[]> {
	return backend.withLock(async () => {
		const recorded = new Set(
			(await backend.readAll()).map((record) => record.id)
		);
		const marked: string[] = [];

		for (const migration of declared) {
			if (recorded.has(migration.id)) continue;
			await backend.write({
				id: migration.id,
				appliedAt: new Date(),
				checksum: checksumOf(migration)
			});
			marked.push(migration.id);
		}

		return marked;
	});
}
