import { createHash, randomBytes } from 'node:crypto';
import { unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { STORAGE_DIVERGENCES } from '../lib/consts/storage_divergences.js';
import {
	FIXED_AREAS,
	STORE_AREAS,
	areaForBucket
} from '../lib/consts/storage_inventory.js';

/*
 * Storage fidelity for the PostgreSQL backend, against a real PostgreSQL.
 *
 *   POSTGRES_URL=postgres://…/oauth_scratch  bun database/verify_postgres.ts
 *
 * DESTRUCTIVE. It creates tables, writes rows no application would write, and refuses to run unless
 * the target database names itself disposable (see the guard below), so it cannot be pointed at production by a stray shell.
 *
 * Constitution Principle III permits a suite that uses a real database under three conditions: it
 * must be invoked separately, must not be reachable from the default run, and must be confined to
 * properties an in-memory double cannot exhibit. This is a script rather than a spec file precisely
 * so `bun test` can never reach it.
 *
 * Everything here earned its place by finding something. Three defects in this backend were invisible
 * to the hermetic suite and visible immediately to a real database — a `Buffer` returning as the
 * wrong kind, a `Date` returning as a string, and documents written as jsonb *strings* so that every
 * predicate reaching inside them silently matched nothing. Each is checked below.
 */

const THROWAWAY =
	/(^|[-_])(test|tmp|scratch|throwaway|migrationcheck)([-_]|$)/i;

const url = process.env.POSTGRES_URL;
if (!url) {
	console.error('POSTGRES_URL must be provided as an env var');
	process.exit(1);
}

/*
 * The blast-radius guard, and the reason this is safe to hand to somebody.
 *
 * A fidelity check has to write to a real database, so the only thing between it and somebody's
 * tenants is which database it is pointed at. Requiring the name to say out loud that it is
 * disposable makes the dangerous case unreachable by accident while costing a deliberate user one
 * word.
 */
const database = new URL(url).pathname.replace(/^\//, '');
if (!THROWAWAY.test(database)) {
	console.error(
		`refusing to run against '${database}': the database name must contain test, tmp, scratch, ` +
			'throwaway or migrationcheck as a whole word. Point POSTGRES_URL at a scratch database.'
	);
	process.exit(1);
}

/*
 * Imported here rather than at the top, and after the guard above has had its say: the adapter index
 * chooses a backend as it evaluates, so a static import would connect — or refuse, on a machine with
 * both connection strings set — before this script had a chance to reject the database name.
 */
const {
	ProtectedResourceStore,
	SingletonSecretStore,
	UserBucketStore,
	UserStore,
	close,
	sql,
	sweepOnce,
	tableExists
} = await import('../lib/adapters/postgres/index.js');
const { columnFor } = await import('../lib/adapters/postgres/jsonPath.js');
const { adapter } = await import('../lib/adapters/index.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

/*
 * How a child process is given exactly one datastore, and why it takes a file.
 *
 * Deleting MONGODB_URI from the environment handed to the child is not enough: Bun loads `.env` and
 * `.env.local` in the child itself, so a developer's leftover Mongo string reappears there and the
 * child is refused for naming two datastores — a refusal this script would then read as the failure
 * it was trying to measure. Two checks passed for exactly that wrong reason before this existed.
 *
 * `--env-file` replaces Bun's default dotenv loading outright, which is the only way to say "these
 * variables and no others". The inherited environment is filtered as well, because a variable
 * exported in the operator's shell is not in any file.
 */
const childFiles: string[] = [];

async function childEnv(
	connection: string
): Promise<{ file: string; env: Record<string, string> }> {
	const file = join(
		tmpdir(),
		`oauth-verify-${process.pid}-${childFiles.length}.env`
	);
	const issuer = process.env.ISSUER ?? 'http://localhost:3000';
	await Bun.write(
		file,
		[
			`POSTGRES_URL=${connection}`,
			`ISSUER=${issuer}`,
			'NODE_ENV=production',
			''
		].join('\n')
	);
	childFiles.push(file);

	const env = { ...process.env } as Record<string, string>;
	delete env.MONGODB_URI;
	delete env.DATABASE_NAME;
	env.POSTGRES_URL = connection;
	return { file, env };
}

const handle = sql();

/* The three secrets share one area, told apart by a derived id — the same derivation the store uses.
 * Duplicated here rather than exported, because a check that reuses the code under test to find its
 * own row proves less than one that arrives at the row independently. */
function secretIdOf(documentName: string): string {
	return createHash('sha256')
		.update(documentName)
		.digest('hex')
		.substring(0, 24);
}

/* ---- 1. bytea: the defect that prompted the constitutional carve-out ------------------------ */

for (const name of ['dpopNonceSecret', 'pairwiseSalt', 'errorOriginSalt']) {
	const store = new SingletonSecretStore(name);

	/*
	 * Start from absent. Provisioning creates two of these three, and `create` is create-if-absent
	 * that returns the winner — so against a provisioned database the round-trip check would compare
	 * this run's candidate against the value provisioning wrote and fail for the wrong reason. That
	 * is the store behaving correctly; the check has to name its own starting state.
	 */
	await handle`
		DELETE FROM ${handle(STORE_AREAS.serviceConfig)}
		WHERE id = ${secretIdOf(name)}
	`;

	const written = randomBytes(32);
	const readBack = await store.create(written);

	check(
		`${name}: reads back as bytes a caller's guard accepts`,
		readBack instanceof Uint8Array,
		`got ${readBack === null ? 'null' : (readBack as object).constructor?.name}`
	);
	check(
		`${name}: round-trips byte for byte`,
		readBack instanceof Uint8Array && Buffer.from(readBack).equals(written)
	);

	/* A losing writer must adopt the winner's value rather than overwrite it — two instances
	 * provisioning the same secret at once is the ordinary case, not a corner one. */
	const second = await store.create(randomBytes(32));
	check(
		`${name}: a second create adopts the stored value instead of replacing it`,
		second instanceof Uint8Array && Buffer.from(second).equals(written)
	);

	/* Conditional replace: two instances that both find an unusable secret must not both install one. */
	const replacement = randomBytes(32);
	const stale = randomBytes(32);
	await store.replace(stale, replacement);
	const afterStale = await store.read();
	check(
		`${name}: replace against a value nobody observed does not take effect`,
		afterStale instanceof Uint8Array && Buffer.from(afterStale).equals(written)
	);

	const afterReal = await store.replace(await store.read(), replacement);
	check(
		`${name}: replace against the observed value does take effect`,
		afterReal instanceof Uint8Array &&
			Buffer.from(afterReal).equals(replacement)
	);
}

/* ---- 2. documents are jsonb objects, not jsonb strings -------------------------------------- */

const shapes = await handle`
	SELECT jsonb_typeof(doc) AS kind, count(*)::int AS held
	FROM ${handle(STORE_AREAS.userBuckets)} GROUP BY 1
`;
check(
	'stored documents are jsonb objects',
	shapes.length > 0 &&
		shapes.every((r: { kind: string }) => r.kind === 'object'),
	shapes
		.map((r: { kind: string; held: number }) => `${r.kind}×${r.held}`)
		.join(', ')
);

/* The consequence, checked directly rather than inferred: a predicate that reaches inside the
 * document has to match. This is what the double-encoding defect broke while every round trip
 * still looked perfect. */
const byName = await handle`
	SELECT id FROM ${handle(STORE_AREAS.userBuckets)} WHERE doc->>'name' = 'Administrators'
`;
check('a predicate inside the document matches', byName.length === 1);

/* ---- 3. dates survive the round trip as dates ----------------------------------------------- */

const users = new UserStore('redfox');
const created = await users.create(
	`fidelity-${Date.now()}@example.com`,
	'not-a-real-hash'
);
const reread = await users.find(created._id);
check(
	'a stored Date reads back as a Date, not a string',
	reread?.createdAt instanceof Date,
	`got ${typeof reread?.createdAt}`
);

/* ---- 4. uniqueness is enforced by the datastore, under concurrency --------------------------- */

const clash = `clash-${Date.now()}@example.com`;
const both = await Promise.allSettled([
	users.create(clash, 'a'),
	users.create(clash, 'b')
]);
check(
	'two simultaneous registrations of one address: exactly one wins',
	both.filter((r) => r.status === 'fulfilled').length === 1,
	both.map((r) => r.status).join(', ')
);

/* The same property one level up, on a different key: a resource identifier is instance-wide unique
 * because it is the primary key, not because a route remembered to look first. */
const resources = new ProtectedResourceStore();
const identifier = `https://fidelity.invalid/api/${Date.now()}`;
const declaredTwice = await Promise.allSettled([
	resources.create({
		_id: identifier,
		projectId: 'fidelity',
		name: 'first',
		scopes: ['read']
	}),
	resources.create({
		_id: identifier,
		projectId: 'fidelity',
		name: 'second',
		scopes: ['read']
	})
]);
check(
	'two simultaneous declarations of one resource identifier: exactly one wins',
	declaredTwice.filter((r) => r.status === 'fulfilled').length === 1,
	declaredTwice.map((r) => r.status).join(', ')
);

/* ---- 5. the sweeper removes what expired, and nothing else ---------------------------------- */

await adapter('AccessToken').upsert('fidelity-expired', { exp: 1 }, -1);
await adapter('AccessToken').upsert('fidelity-live', { exp: 9e9 }, 3600);
await adapter('Client').upsert('fidelity-permanent', { clientId: 'x' });

const swept = await sweepOnce();
check(
	'the sweeper removes an expired record',
	(await adapter('AccessToken').find('fidelity-expired')) === undefined,
	`${swept} row(s) reclaimed`
);
check(
	'the sweeper leaves a live record alone',
	(await adapter('AccessToken').find('fidelity-live')) !== undefined
);
check(
	'the sweeper never touches an area declared permanent',
	(await adapter('Client').find('fidelity-permanent')) !== undefined
);

/* A row in a reaped area that carries no expiry at all. The partial index the sweep rides on is
 * `WHERE expires_at IS NOT NULL`, so this row is invisible to it — which is the intended answer, and
 * worth asserting rather than assuming, because the alternative (a sweep that reads NULL as "long
 * ago") deletes live records. */
const handleForNulls = sql();
await handleForNulls`
	INSERT INTO ${handleForNulls('AccessToken')} (id, payload, expires_at)
	VALUES ('fidelity-no-expiry', ${{ exp: 9e9 }}, NULL)
	ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, expires_at = NULL
`;
await sweepOnce();
check(
	'the sweeper leaves a row with no expiry in a reaped area alone',
	(await adapter('AccessToken').find('fidelity-no-expiry')) !== undefined
);

/* ---- 6. the provisioned area set ------------------------------------------------------------ */

const missing: string[] = [];
for (const area of FIXED_AREAS) {
	if (!(await tableExists(handle, area.name))) missing.push(area.name);
}

/* Read the bucket list from the table rather than naming the two seeded ones, so a bucket this run
 * created is swept too — that is the case the section-7 sweep below was added for. */
const runtimeAreas = (
	await handle`SELECT id FROM ${handle(STORE_AREAS.userBuckets)}`
).map((row: { id: string }) => areaForBucket(row.id));

for (const area of runtimeAreas) {
	if (!(await tableExists(handle, area.name))) missing.push(area.name);
}
check('every declared area exists', missing.length === 0, missing.join(', '));

/*
 * A bucket created the way an administrator creates one — through the store the console calls, not
 * through the provisioning script. Its user table has to exist *and* be constrained at that moment:
 * a bucket added after deployment whose table carried no unique-email index is exactly the
 * registration race the constraint is there to make unwinnable.
 */
const buckets = new UserBucketStore();
const runtime = await buckets.create({
	name: `fidelity-${Date.now()}`,
	ownerGroupId: 'unassigned'
});
const runtimeArea = areaForBucket(runtime._id);
check(
	'a bucket created at runtime gets its area',
	await tableExists(handle, runtimeArea.name),
	runtimeArea.name
);

const runtimeUsers = new UserStore(runtime._id);
const shared = `runtime-${Date.now()}@example.com`;
const racing = await Promise.allSettled([
	runtimeUsers.create(shared, 'a'),
	runtimeUsers.create(shared, 'b')
]);
check(
	'and its constraint, applied at creation rather than at the next provisioning run',
	racing.filter((r) => r.status === 'fulfilled').length === 1,
	racing.map((r) => r.status).join(', ')
);

/*
 * Two driver behaviours the plan named as risks (research D1). `timestamptz` must come back as a
 * Date in its own right, and `int8` comes back as a *string* — deliberately, since a 64-bit integer
 * does not fit a JavaScript number. Both are checked against the driver rather than trusted, because
 * a change in either would surface as a wrong value somewhere far from here.
 */
const [types] = await handle`
	SELECT now() AS moment, (2 ^ 62)::int8 AS big, count(*)::int AS counted
	FROM ${handle(STORE_AREAS.userBuckets)}
`;
check(
	'timestamptz reads back as a Date',
	(types as { moment: unknown }).moment instanceof Date
);
check(
	'int8 reads back as a string, so 64-bit values survive',
	typeof (types as { big: unknown }).big === 'string',
	`got ${typeof (types as { big: unknown }).big}`
);
check(
	'and an int4 count reads back as a number, which is why counts are cast',
	typeof (types as { counted: unknown }).counted === 'number'
);

/*
 * Provisioning is idempotent, checked by running the real script rather than by re-calling the
 * function it happens to use: the claim operators rely on is about `bun run db:setup:pg`, including
 * its seeding and its migration baseline, not about one helper inside it.
 */
const reprovisionEnv = await childEnv(url);
const reprovision = Bun.spawn(
	['bun', '--env-file', reprovisionEnv.file, 'database/postgres.ts'],
	{ env: reprovisionEnv.env, stdout: 'pipe', stderr: 'pipe' }
);
const reprovisionStatus = await reprovision.exited;
const reprovisionOut = await new Response(reprovision.stdout).text();
check(
	'a second provisioning run reports no work and exits clean',
	reprovisionStatus === 0 &&
		/0 area\(s\) created, 0 index\(es\) created/.test(reprovisionOut),
	reprovisionOut.trim().split('\n').at(-1) ?? ''
);

/* ---- 7. no row anywhere holds a jsonb string ------------------------------------------------ */

/*
 * The whole-database sweep, and the reason it exists rather than the spot check above.
 *
 * Section 2 asks whether the rows *provisioning* wrote are jsonb objects, which is where the defect
 * was first seen. That is not the same question as "does every write site in this codebase pass an
 * object", and the difference is not academic: re-introducing the bug in `userBucketStore.create`
 * was invisible to section 2, because the row it writes is created later in this file than the check
 * that would have caught it. A check whose coverage depends on statement order is a check that will
 * be wrong again.
 *
 * So this runs last, over every table the run has touched, and asks the question of all of them at
 * once. It is the check that actually holds the contract `lib/adapters/postgres/json.ts` describes.
 */
const stringy: string[] = [];
for (const area of [...FIXED_AREAS, ...runtimeAreas]) {
	if (!(await tableExists(handle, area.name))) continue;

	const column = columnFor(area);
	const [bad] = await handle`
		SELECT count(*)::int AS held FROM ${handle(area.name)}
		WHERE ${handle(column)} IS NOT NULL AND jsonb_typeof(${handle(column)}) <> 'object'
	`;
	const held = (bad as { held: number }).held;
	if (held > 0) stringy.push(`${area.name}×${held}`);
}
check(
	'every document column in every area holds an object, not a jsonb string',
	stringy.length === 0,
	stringy.join(', ')
);

/* ---- 8. the declared divergences, observed against a real database ------------------------- */

/*
 * What makes the register a gate rather than a document: each entry that claims something about
 * this backend is checked against what the backend actually does, so an entry that stops being true
 * fails here instead of quietly misleading the next reader.
 *
 * The register's own well-formedness — unique ids, a reason and an observable in words — needs no
 * database and lives in `test/storage_contract/divergence_register.spec.ts`, where it runs on every
 * commit rather than only when somebody points this script at PostgreSQL.
 */

function declared(id: string): boolean {
	return STORAGE_DIVERGENCES.some((d) => d.id === id);
}

/*
 * Deliberately does what production never does: `Client` is `reaped: null` and receives no ttl from
 * any call site, which is the invariant `test/storage_contract/ttl_pairing.spec.ts` holds and the
 * reason the difference below is unobservable. Reproducing the case by hand is the only way to see
 * what it would do, and a scratch database is the only place it is allowed.
 */
const untimed = 'fidelity-untimed';
await adapter('Client').upsert(untimed, { clientId: untimed }, 3600);
await adapter('Client').upsert(untimed, { clientId: untimed });
const [afterUntimed] = await handle`
	SELECT expires_at FROM ${handle('Client')} WHERE id = ${untimed}
`;
check(
	"'stale-expiry-on-untimed-upsert' still describes what this backend does",
	declared('stale-expiry-on-untimed-upsert') &&
		afterUntimed?.expires_at === null,
	`expires_at ${String(afterUntimed?.expires_at)}`
);

let refusedWrite = false;
try {
	await handle`INSERT INTO ${handle('fidelityNoSuchArea')} (id) VALUES ('x')`;
} catch {
	refusedWrite = true;
}
check(
	"'unprovisioned-area-on-first-write' still describes what this backend does",
	declared('unprovisioned-area-on-first-write') && refusedWrite
);

/* ---- 9. a server whose datastore is unreachable does not start ------------------------------ */

/*
 * The other half of the probe pair, and the half a script can actually assert.
 *
 * A lazily connecting handle is what keeps the module graph clean (research D1), and it is also what
 * would let this server come up happily against a dead PostgreSQL and start answering — the failure
 * an eagerly connecting MongoDB never had. The startup gate closes that, and this is the check that
 * it stays closed: boot the app with the connection string pointed at a port nothing listens on, and
 * the process must die rather than serve.
 *
 * The complementary case — stopping the datastore *under* a running server and watching liveness hold
 * at 200 while readiness turns 503 and recovers unaided — needs control of the database process, so
 * it stays a hand-run step in the quickstart rather than being faked here.
 */

const dead = new URL(url);
dead.hostname = '127.0.0.1';
dead.port = '1';

const bootEnv = await childEnv(dead.toString());
const boot = Bun.spawn(
	['bun', '--env-file', bootEnv.file, '-e', "await import('./lib/index.ts')"],
	{ env: bootEnv.env, stdout: 'pipe', stderr: 'pipe' }
);

const bootTimeout = setTimeout(() => boot.kill(), 60_000);
const bootStatus = await boot.exited;
clearTimeout(bootTimeout);
const bootOutput = await new Response(boot.stderr).text();

check(
	'a server whose datastore is unreachable refuses to start',
	bootStatus !== 0,
	`exit ${bootStatus}`
);
check(
	'and says which datastore it could not reach',
	/*
	 * Naming the datastore is necessary and nowhere near sufficient, and this assertion learned that
	 * the hard way: it passed against the two-connection-strings refusal, whose text also says
	 * PostgreSQL. It has to be a *connection* failure — the child tried to reach the database and
	 * could not, rather than being turned away before it looked.
	 */
	!/both/i.test(bootOutput) &&
		/PostgresError|ERR_POSTGRES_CONNECTION_REFUSED/.test(bootOutput),
	/* The first line that is a message rather than a frame of the code that raised it. */
	bootOutput
		.split('\n')
		.map((line) => line.trim())
		.filter((line) => !/^[0-9]+ \|/.test(line))
		.find((line) => /^[A-Za-z]*Error|^error:/.test(line)) ??
		bootOutput.slice(0, 120)
);

console.log(
	`\n${failures === 0 ? 'all fidelity checks passed' : `${failures} check(s) FAILED`}`
);

for (const file of childFiles) await unlink(file).catch(() => undefined);

await close();
process.exit(failures === 0 ? 0 : 1);
