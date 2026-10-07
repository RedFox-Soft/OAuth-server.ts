import { MIGRATIONS } from '../lib/consts/migrations.js';
import { selectBackend } from '../lib/adapters/selectBackend.js';
import { MigrationLockBusy } from '../lib/migrations/lock.js';
import { migrationBackend } from '../lib/migrations/backend.js';
import { plan, run } from '../lib/migrations/runner.js';
import { isNoop, type Migration } from '../lib/consts/migrations.js';

/*
 * Applies outstanding schema migrations to whichever datastore is configured.
 *
 *   bun run db:migrate            apply
 *   bun run db:migrate --plan     report what would run, change nothing
 *
 * One command for both backends, with the same output shape and the same exit codes, because an
 * operator moving a deployment between datastores should not have to learn a second procedure.
 *
 * On a deployment with nothing outstanding this reports "current" and exits.
 */

const PLAN_ONLY = process.argv.includes('--plan');

const backendName = selectBackend(process.env);
if (backendName === 'memory') {
	console.error(
		'no datastore is configured, so there is nothing to migrate. Set MONGODB_URI or POSTGRES_URL.'
	);
	process.exit(1);
}

/*
 * Imported only now, and only the one that was selected.
 *
 * `lib/adapters/index.ts` constructs every store as a side effect of being imported and reaches the
 * configuration, which reads from the datastore. That is fine here — a migration run happens against a
 * provisioned database — but it is the reason this is a dynamic import after the environment check
 * rather than a top-level one before it.
 */
const { getMigrationLeaseStore, getSchemaMigrationStore } =
	await import('../lib/adapters/index.js');

const records = getSchemaMigrationStore();
const lease = getMigrationLeaseStore();

/*
 * The handle a step's `apply` receives: the driver's database for MongoDB, the SQL client for
 * PostgreSQL. Omitted while every declared migration was a no-op, which is how the first real one would
 * have been handed `undefined`.
 */
const handle =
	backendName === 'postgres'
		? (await import('../lib/adapters/postgres/db.js')).sql()
		: (await import('../lib/adapters/mongodb/db.js')).db;

const backend = migrationBackend(
	backendName,
	{
		readAll: () => records.all(),
		write: (entry) => records.record(entry),
		lease
	},
	handle
);

function describe(migration: Migration): string {
	const half =
		backendName === 'postgres' ? migration.postgres : migration.mongodb;
	const shape = isNoop(half) ? ` (no-op here: ${half.reason})` : '';
	const oneWay = migration.reversible ? '' : '  [NOT REVERSIBLE]';
	return `  ${migration.id}  ${migration.description}${shape}${oneWay}`;
}

function report(status: string, outstanding: readonly string[]): void {
	const pending = MIGRATIONS.filter((m) => outstanding.includes(m.id));
	for (const migration of pending) console.log(describe(migration));

	/*
	 * Named separately rather than left to the line above. A migration that cannot be undone is the one
	 * thing an operator must see before deciding, and a flag inside a list of a dozen lines is a flag
	 * that gets skimmed past.
	 */
	const oneWay = pending.filter((migration) => !migration.reversible);
	if (oneWay.length > 0) {
		console.log(
			`\n${oneWay.length} of these cannot be undone: ${oneWay
				.map((m) => m.id)
				.join(', ')}. Restoring a backup is the only way back.`
		);
	}

	console.log(`\nstatus: ${status}`);
}

try {
	if (PLAN_ONLY) {
		const state = await plan(MIGRATIONS, backend);
		if (state.outstanding.length === 0 && state.status === 'current') {
			console.log('status: current — nothing to apply');
			process.exit(0);
		}
		report(state.status, state.outstanding);
		/* Non-zero so a deployment pipeline can gate on "needs migrating" without parsing output. */
		process.exit(state.status === 'current' ? 0 : 1);
	}

	const before = await plan(MIGRATIONS, backend);

	if (before.status === 'ahead') {
		console.error(
			`this database was migrated by a newer release: ${before.unknown.join(', ')}. ` +
				'Upgrade the server rather than migrating the database backwards; nothing was changed.'
		);
		process.exit(1);
	}
	if (before.status === 'diverged') {
		console.error(
			`these migrations are recorded under declarations that have since changed: ${before.mismatched.join(', ')}. ` +
				'A released migration must not be edited; nothing was changed.'
		);
		process.exit(1);
	}
	if (before.status === 'current') {
		console.log('status: current — nothing to apply');
		process.exit(0);
	}

	console.log(`applying ${before.outstanding.length} migration(s):`);
	report('applying', before.outstanding);

	const result = await run(MIGRATIONS, backend);
	for (const [id, lines] of Object.entries(result.reports ?? {})) {
		console.log(`\n${id}:`);
		for (const line of lines) console.log(`  ${line}`);
	}
	console.log(
		`\ndone: ${result.applied.length} applied, ${result.skipped.length} recorded as no-ops here`
	);
	process.exit(0);
} catch (error) {
	if (error instanceof MigrationLockBusy) {
		console.error(error.message);
		process.exit(1);
	}
	/* Never echoes the connection string: a migration log is the kind of output that gets pasted into
	 * an issue. */
	console.error(`migration failed: ${(error as Error).message}`);
	console.error(
		'Everything applied before the failure stays recorded, so re-running resumes rather than restarts.'
	);
	process.exit(1);
}
