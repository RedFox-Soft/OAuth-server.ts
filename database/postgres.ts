import {
	FIXED_AREAS,
	areaForBucket,
	userAreaFor,
	type StorageArea
} from '../lib/consts/storage_inventory.js';
import { selectBackend } from '../lib/adapters/selectBackend.js';
import {
	applyIndexes,
	close,
	ensureTable,
	indexStatements,
	isInsufficientPrivilege,
	provisionUserArea,
	sql,
	tableExists,
	JWKSStore
} from '../lib/adapters/postgres/index.js';
import {
	duplicateEmailReport,
	exitCodeFor,
	type DuplicateEmailRow,
	type ProvisioningSummary
} from './provisioning_report.js';
import { generateJWKS } from '../lib/helpers/jwks.js';
import { MIGRATIONS } from '../lib/consts/migrations.js';
import { migrationBackend } from '../lib/migrations/backend.js';
import { baseline } from '../lib/migrations/runner.js';

/*
 * Prepares a PostgreSQL database for this server: every declared storage area, every index the
 * inventory derives for it, the reserved administrator seed, and an initial signing key.
 *
 *   bun run db:setup:pg              provision and seed
 *   bun run db:setup:pg --check      report what disagrees, change nothing
 *
 * Idempotent, and safe to re-run after upgrading — that is how a newly declared area reaches an
 * existing database.
 *
 * Two things about the shape are deliberate. It imports the PostgreSQL adapter directly, which is
 * possible only because that module connects lazily; the MongoDB script cannot do the same and writes
 * raw documents instead. And the *seed* is a deferred import at the very end, for a reason worth
 * stating: `lib/admin/seed.ts` reaches the model graph, which reads the persisted configuration at
 * module load — importing it before the tables exist would read a table that is not there yet.
 */

const CHECK_ONLY = process.argv.includes('--check');

/*
 * The same rule the server applies, so a misconfigured environment is refused here rather than
 * discovered after the script has written half a schema.
 */
const backend = selectBackend(process.env);
if (backend !== 'postgres') {
	console.error(
		backend === 'mongodb'
			? 'MONGODB_URI is set and POSTGRES_URL is not — run `bun run db:setup` for MongoDB.'
			: 'POSTGRES_URL must be provided as an env var.'
	);
	process.exit(1);
}

const summary: ProvisioningSummary = {
	collectionsCreated: 0,
	indexesCreated: 0,
	indexesDropped: 0,
	bucketsProcessed: 0,
	constraintsSkipped: 0
};

/*
 * Nothing here ever prints the connection string or any part of it. A provisioning log is the kind of
 * output that gets pasted into an issue.
 */
function fail(context: string, error: unknown): never {
	if (isInsufficientPrivilege(error)) {
		console.error(
			`${context}: the configured role lacks CREATE privilege on this database. ` +
				'Grant it and re-run; nothing was changed.'
		);
	} else {
		console.error(`${context}: ${(error as Error).message}`);
	}
	process.exit(1);
}

/* Which index names an area already carries, read from the catalog rather than inferred. */
async function existingIndexNames(area: string): Promise<Set<string>> {
	const handle = sql();
	const rows = await handle`
		SELECT indexname FROM pg_indexes WHERE tablename = ${area}
	`;
	return new Set(
		rows.map((row: unknown) => (row as { indexname: string }).indexname)
	);
}

/*
 * Reports what disagrees, changing nothing.
 *
 * Compares by presence, not by shape. An index that exists under the declared name but was built
 * differently is not detected here, and saying so is better than implying a completeness this cannot
 * deliver: PostgreSQL reports an index as normalised definition text, and comparing that reliably
 * needs either a parser or a canonicalisation pass whose mistakes would report drift that is not
 * there. The local-instance verification is where shape is proved.
 */
async function check(): Promise<number> {
	let disagreements = 0;

	for (const area of await allAreas()) {
		if (!(await tableExists(sql(), area.name))) {
			console.error(`missing area ${area.name}`);
			disagreements += 1;
			continue;
		}

		const present = await existingIndexNames(area.name);
		for (const planned of indexStatements(area)) {
			if (!present.has(planned.name)) {
				console.error(`missing index ${planned.name} on ${area.name}`);
				disagreements += 1;
			}
		}
	}

	console.log(
		disagreements === 0
			? 'schema agrees with the declared inventory'
			: `${disagreements} disagreement(s) with the declared inventory; nothing was changed`
	);
	return disagreements === 0 ? 0 : 1;
}

/* Every area a provisioned database should hold: the fixed ones, plus one per bucket that exists. */
async function allAreas(): Promise<StorageArea[]> {
	const handle = sql();
	const areas = [...FIXED_AREAS];

	/* Read straight from the table rather than through the bucket store, so `--check` works on a
	 * database the application graph could not yet be loaded against. */
	if (await tableExists(handle, 'userBuckets')) {
		const rows = await handle`SELECT id FROM ${handle('userBuckets')}`;
		for (const row of rows) {
			areas.push(areaForBucket((row as { id: string }).id));
		}
	}

	return areas;
}

async function provisionArea(
	area: StorageArea,
	{
		blockUnique = false,
		note = ''
	}: { blockUnique?: boolean; note?: string } = {}
): Promise<void> {
	const handle = sql();

	if (await ensureTable(handle, area)) {
		console.log(`created area ${area.name}${note}`);
		summary.collectionsCreated += 1;
	}

	/*
	 * Nothing is ever dropped. The MongoDB routine drops a stale *expiry* index because an undeclared
	 * schedule that deletes records is worse than leaving it; PostgreSQL has no expiry index at all —
	 * the sweeper replaces it — so the subtractive half of provisioning has nothing to act on here.
	 */
	const present = await existingIndexNames(area.name);
	const planned = indexStatements(area).filter(
		(index) => !present.has(index.name)
	);

	/* Blocking the unique ones still applies the rest, so one bucket's bad data leaves nothing else
	 * unprovisioned. The subset is passed through rather than filtered afterwards — applying an index
	 * and then not counting it would be the bug this replaced. */
	const appliable = blockUnique
		? planned.filter((index) => !index.statement.startsWith('CREATE UNIQUE'))
		: planned;
	summary.constraintsSkipped += planned.length - appliable.length;

	if (appliable.length === 0) return;

	const { created, conflicted } = await applyIndexes(handle, area, appliable);
	for (const index of created) {
		console.log(`created index ${index.name} on ${area.name}`);
		summary.indexesCreated += 1;
	}
	for (const index of conflicted) {
		console.error(
			`${area.name}: skipped index ${index.name} — an incompatible object of ` +
				'that name already exists; drop it by hand and re-run'
		);
		summary.constraintsSkipped += 1;
	}
}

/*
 * Addresses already duplicated in a bucket, which would make the unique index refuse to build.
 *
 * Pre-checked rather than left to the failure, which names one offending value and says nothing about
 * the rest. Resolving the conflict is the operator's: deleting a record is forbidden here, and
 * choosing which of two accounts survives is a product decision.
 */
async function duplicateEmails(area: string): Promise<DuplicateEmailRow[]> {
	const handle = sql();
	if (!(await tableExists(handle, area))) return [];

	const rows = await handle`
		SELECT doc->>'email' AS value, count(*)::int AS count
		FROM ${handle(area)}
		WHERE doc->>'email' IS NOT NULL
		GROUP BY doc->>'email'
		HAVING count(*) > 1
		ORDER BY doc->>'email'
	`;
	return rows as DuplicateEmailRow[];
}

if (CHECK_ONLY) {
	let code = 1;
	try {
		code = await check();
	} catch (error) {
		fail('reading the schema', error);
	}
	await close();
	process.exit(code);
}

for (const area of FIXED_AREAS) {
	try {
		await provisionArea(area);
	} catch (error) {
		fail(`provisioning ${area.name}`, error);
	}
}

/*
 * The initial signing key, so a freshly provisioned database already holds a persisted RS256 key. The
 * runtime loader keeps an equivalent generate-on-empty fallback, but doing it here means the key
 * exists before anything reads it — and makes the provisioning run, rather than the first request,
 * the moment a deployment's key is created.
 */
const jwks = new JWKSStore();
if ((await jwks.getAll()).length === 0) {
	const {
		keys: [key]
	} = await generateJWKS();
	if (key?.kid) {
		await jwks.set(key.kid, key);
		console.log(`created the initial RS256 signing key ${key.kid}`);
	}
}

/*
 * The seed, imported only now.
 *
 * `lib/admin/seed.ts` reaches the model graph, and that graph reads the persisted configuration at
 * module load — so importing it any earlier would read a table that does not exist yet. Deferring it
 * is what lets this script reuse the shared seed path instead of hand-writing a third copy of the
 * documents, which is what the MongoDB script has to do.
 */
const { ensureAdminSeed } = await import('../lib/admin/seed.js');
try {
	await ensureAdminSeed();
} catch (error) {
	fail('seeding the reserved administrator records', error);
}

/*
 * Baseline the migration record.
 *
 * A database provisioned from empty is at the current shape by construction — this routine built what
 * the current release declares — so every declared migration is marked applied without being run.
 * Replaying the history that led here would at best do nothing and at worst rewrite data the release
 * never had.
 *
 * Deliberately not the same as "the record table is empty": a real deployment that predates the first
 * migration also has none, and baselining it would skip work it genuinely needs. Only this script
 * knows it just created the schema, which is why the decision is here and not inside the runner.
 */
const { getMigrationLeaseStore, getSchemaMigrationStore } =
	await import('../lib/adapters/index.js');
const marked = await baseline(
	MIGRATIONS,
	migrationBackend('postgres', {
		readAll: () => getSchemaMigrationStore().all(),
		write: (entry) => getSchemaMigrationStore().record(entry),
		lease: getMigrationLeaseStore()
	})
);
if (marked.length > 0) {
	console.log(`baselined ${marked.length} declared migration(s) as applied`);
}

/*
 * Per-bucket end-user areas. Buckets created later through the admin console provision their own
 * table inline, so this covers the upgrade case: a bucket that existed before this release, or before
 * a newly declared index on the per-bucket area.
 */
const handle = sql();
const bucketRows = await handle`SELECT id FROM ${handle('userBuckets')}`;
for (const row of bucketRows) {
	const bucketId = (row as { id: string }).id;
	const area = areaForBucket(bucketId);

	const report = duplicateEmailReport(
		bucketId,
		await duplicateEmails(userAreaFor(bucketId))
	);
	if (report) {
		console.error(report);
		summary.constraintsSkipped += 1;
	}

	try {
		// Everything except the blocked unique constraint is still applied: one bucket's bad data must
		// not leave the rest of that bucket — or any other — unprovisioned.
		await provisionArea(area, {
			blockUnique: report !== null,
			note: ` for bucket ${bucketId}`
		});
		if (report === null) await provisionUserArea(handle, bucketId);
	} catch (error) {
		fail(`provisioning the end-user area for bucket ${bucketId}`, error);
	}
	summary.bucketsProcessed += 1;
}

console.log(
	`done: ${summary.collectionsCreated} area(s) created, ` +
		`${summary.indexesCreated} index(es) created, ` +
		`${summary.bucketsProcessed} bucket(s) processed` +
		(summary.constraintsSkipped > 0
			? `, ${summary.constraintsSkipped} constraint(s) skipped`
			: '')
);

await close();
process.exit(exitCodeFor(summary));
