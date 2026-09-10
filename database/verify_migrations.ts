import { hostname } from 'node:os';

import type { Migration } from '../lib/consts/migrations.js';
import { migrationBackend } from '../lib/migrations/backend.js';
import { MigrationLockBusy, withLease } from '../lib/migrations/lock.js';
import { baseline, plan, run } from '../lib/migrations/runner.js';
import { compare } from '../lib/migrations/state.js';
import { close, sql } from '../lib/adapters/postgres/index.js';

/*
 * The migration layer, against a real PostgreSQL.
 *
 *   POSTGRES_URL=postgres://…/oauth_scratch  bun database/verify_migrations.ts
 *
 * DESTRUCTIVE, and refuses any database whose name does not say it is disposable — the same guard
 * `verify_postgres.ts` carries, for the same reason.
 *
 * Runs against a FIXTURE migration set, not the declared one. The declared set ships empty, so
 * verifying it would verify nothing; the machinery is what has to work before the first real
 * migration is written, and this is the only place it meets a real database — records that survive a
 * process, a lease two runners actually contend for, and a failure that leaves the earlier steps
 * recorded.
 */

const THROWAWAY =
	/(^|[-_])(test|tmp|scratch|throwaway|migrationcheck)([-_]|$)/i;

const url = process.env.POSTGRES_URL;
if (!url) {
	console.error('POSTGRES_URL must be provided as an env var');
	process.exit(1);
}

const database = new URL(url).pathname.replace(/^\//, '');
if (!THROWAWAY.test(database)) {
	console.error(
		`refusing to run against '${database}': the database name must contain test, tmp, scratch, ` +
			'throwaway or migrationcheck as a whole word. Point POSTGRES_URL at a scratch database.'
	);
	process.exit(1);
}

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const { getMigrationLeaseStore, getSchemaMigrationStore } =
	await import('../lib/adapters/index.js');
const records = getSchemaMigrationStore();
const lease = getMigrationLeaseStore();

const backend = migrationBackend('postgres', {
	readAll: () => records.all(),
	write: (entry) => records.record(entry),
	lease
});

const ran: string[] = [];
let failing = true;

function migration(id: string, extra: Partial<Migration> = {}): Migration {
	return {
		id,
		description: `fixture ${id}`,
		reversible: true,
		rerunnable: 'writes nothing; this fixture only records that it ran',
		mongodb: { noop: true, reason: 'fixture is PostgreSQL-only' },
		postgres: {
			apply: async () => {
				ran.push(id);
			}
		},
		...extra
	};
}

const SET = [
	migration('9001-first'),
	migration('9002-fails-once', {
		postgres: {
			apply: async () => {
				if (failing) throw new Error('deliberate fixture failure');
				ran.push('9002-fails-once');
			}
		}
	}),
	migration('9003-third')
];

await records.reset();

/* ---- applying, and recording what was applied ------------------------------------------------ */

await plan(SET, backend).then((state) =>
	check(
		'an empty record reports every migration outstanding',
		state.status === 'behind' && state.outstanding.length === 3
	)
);

/* The first run stops at the failure. What matters is not the failure but what survives it. */
let threw = false;
try {
	await run(SET, backend);
} catch {
	threw = true;
}
check('a failing step aborts the run', threw);
check(
	'the steps before the failure ran',
	ran.join(',') === '9001-first',
	ran.join(',')
);
check(
	'and are recorded, so a re-run resumes rather than restarts',
	(await records.all()).map((r) => r.id).join(',') === '9001-first'
);

failing = false;
const resumed = await run(SET, backend);
check(
	'the re-run applies only what was outstanding',
	resumed.applied.join(',') === '9002-fails-once,9003-third',
	resumed.applied.join(',')
);
check(
	'and the database is then current',
	(await plan(SET, backend)).status === 'current'
);

const second = await run(SET, backend);
check('a further run applies nothing', second.applied.length === 0);

/* ---- records survive the process, which is the whole point of storing them ------------------- */

const persisted = await records.all();
check(
	'every record carries an applied-at Date, not a string',
	persisted.length === 3 && persisted.every((r) => r.appliedAt instanceof Date),
	persisted.map((r) => typeof r.appliedAt).join(',')
);

/* ---- ahead and diverged are refused rather than repaired ------------------------------------- */

const older = SET.slice(0, 2);
check(
	'a database holding a record this release does not declare reads as ahead',
	compare(older, persisted).status === 'ahead'
);

const edited = SET.map((m) =>
	m.id === '9001-first' ? { ...m, description: 'quietly changed' } : m
);
check(
	'a released migration edited after the fact reads as diverged',
	compare(edited, persisted).status === 'diverged'
);
const refusedDiverged = await run(edited, backend);
check(
	'and the runner applies nothing against it',
	refusedDiverged.applied.length === 0 && refusedDiverged.status === 'diverged'
);

/* ---- the lease, contended for real ------------------------------------------------------------ */

const mine = `${hostname()}:${process.pid}`;
let refused = false;
await withLease(lease, mine, async () => {
	try {
		await withLease(lease, `${mine}:other`, async () => undefined);
	} catch (error) {
		refused = error instanceof MigrationLockBusy;
	}
});
check('a second holder is refused while a live lease stands', refused);

const held = await lease.read();
check('and the lease is released when the run finishes', held === null);

await lease.acquire('dead-runner', new Date(Date.now() - 1000));
let tookOver = false;
await withLease(lease, mine, async () => {
	tookOver = true;
});
check(
	'an expired lease is taken over, so a crashed run blocks nobody',
	tookOver
);

/* ---- baseline ---------------------------------------------------------------------------------- */

await records.reset();
const marked = await baseline(SET, backend);
check(
	'baseline records every declared migration without running any',
	marked.length === 3 && (await plan(SET, backend)).status === 'current'
);
const before = ran.length;
await run(SET, backend);
check('and nothing runs afterwards', ran.length === before);

/* Leave the database as the provisioning routine would: no fixture records. */
await records.reset();
await sql()`SELECT 1`;

console.log(
	`\n${failures === 0 ? 'all migration checks passed' : `${failures} check(s) FAILED`}`
);

await close();
process.exit(failures === 0 ? 0 : 1);
