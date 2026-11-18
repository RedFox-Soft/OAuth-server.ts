/*
 * A person's activity (specs/133) against a real datastore: what the in-memory store cannot show.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_person_activity.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_person_activity.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. It writes and then removes its own records, and refuses a database
 * whose name does not say it is disposable, as the other verify scripts do.
 *
 * A script rather than a spec (Constitution Principle III): the in-memory store adds with no `await` inside a write,
 * so `bun test` cannot prove that two writes of one row add up on MongoDB and PostgreSQL, that writes landing out of
 * order keep the earliest first time and the latest last time, that two processes writing overlapping rows at once
 * lose nothing and do not deadlock, or that the expiry index exists.
 *
 * Spec 134 adds what a person used: that an API row keeps the same bounded list of tools on both backends (MongoDB's
 * update pipeline under the strict Stable API, a name beginning $ included), that a project's use adds up to one row
 * a person and app, that the refusals read sees only refusals and has its index, and that the list of people's
 * "Last active" filter and column agree with the marks.
 */

const THROWAWAY =
	/(^|[-_])(test|tmp|scratch|throwaway|migrationcheck)([-_]|$)/i;

const mongo = process.env.MONGODB_URI;
const postgres = process.env.POSTGRES_URL;
if (Boolean(mongo) === Boolean(postgres)) {
	console.error('set exactly one of MONGODB_URI and POSTGRES_URL');
	process.exit(1);
}
const database = mongo
	? (process.env.DATABASE_NAME ?? '')
	: new URL(postgres ?? '').pathname.replace(/^\//, '');
if (!THROWAWAY.test(database)) {
	console.error(
		`refusing to run against '${database}': the database name must contain test, tmp, scratch, ` +
			'throwaway or migrationcheck as a whole word.'
	);
	process.exit(1);
}

/* After the guard, for the reason verify_postgres.ts gives: importing the adapters connects. */
const { getActivityStore, getPersonActivityStore, getUserStore } =
	await import('../lib/adapters/index.js');
const { DEFAULT_BUCKET_ID } = await import('../lib/admin/consts.js');
const { STORE_AREAS } = await import('../lib/consts/storage_inventory.js');
type Row = import('../lib/adapters/types.js').PersonActivityRow;

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const store = getPersonActivityStore();
const stamp = Date.now();
const bucketId = `verify-activity-${stamp}`;
const other = `verify-activity-other-${stamp}`;
const base = new Date();
const at = (seconds: number) => new Date(base.getTime() + seconds * 1000);
const DAY = 86_400_000;

function row(id: string, fields: Partial<Row> = {}): Row {
	const lastAt = fields.lastAt ?? at(0);
	return {
		_id: id,
		bucketId,
		accountId: 'anna',
		day: lastAt.toISOString().slice(0, 10),
		kind: 'signIn',
		outcome: 'refused',
		reason: 'wrong_password',
		place: { clientId: 'acme-web' },
		count: 1,
		firstAt: fields.firstAt ?? lastAt,
		lastAt,
		expiresAt: new Date(lastAt.getTime() + 90 * DAY),
		...fields
	};
}

const page = (accountId = 'anna', limit = 50) =>
	store.listForPerson(bucketId, accountId, { limit, now: new Date() });

/* ---------------------------------------------------------- adding up */

await store.write([row('one', { count: 2 })]);
await store.write([row('one', { count: 3 })]);
const added = (await page()).rows.find((r) => r._id === 'one');
check(
	'two writes of one row add their counts',
	added?.count === 5,
	String(added?.count)
);

await store.write([row('order', { firstAt: at(10), lastAt: at(10) })]);
await store.write([row('order', { firstAt: at(-30), lastAt: at(-30) })]);
await store.write([
	row('order', {
		firstAt: at(5),
		lastAt: at(50),
		address: '203.0.113.9',
		addressFrom: 'sign_in'
	})
]);
const ordered = (await page()).rows.find((r) => r._id === 'order');
check(
	'writes out of order keep the earliest first time and the latest last time',
	ordered?.firstAt.getTime() === at(-30).getTime() &&
		ordered.lastAt.getTime() === at(50).getTime(),
	`${ordered?.firstAt.toISOString() ?? '-'} … ${ordered?.lastAt.toISOString() ?? '-'}`
);
check(
	'the expiry follows the latest write',
	ordered?.expiresAt.getTime() === at(50).getTime() + 90 * DAY
);
check(
	'a write with an address sets it, and its times read back as dates',
	ordered?.address === '203.0.113.9' &&
		ordered.firstAt instanceof Date &&
		ordered.expiresAt instanceof Date
);

/* ---------------------------------------------------------- two processes at once */

const ids = Array.from(
	{ length: 300 },
	(_, i) => `race-${String(i).padStart(3, '0')}`
);
const forward = ids.map((id) => row(id));
const backward = [...ids].reverse().map((id) => row(id));
const results = await Promise.all([
	store.write(forward),
	store.write(backward)
]);
const raced = (
	await store.listForPerson(bucketId, 'anna', { limit: 500, now: new Date() })
).rows.filter((r) => r._id.startsWith('race-'));
check(
	'two writes of overlapping rows in opposite orders both apply, without a deadlock',
	results.every((r) => r.failed === 0) &&
		raced.length === 300 &&
		raced.every((r) => r.count === 2),
	JSON.stringify({
		failed: results.map((r) => r.failed),
		rows: raced.length,
		counts: [...new Set(raced.map((r) => r.count))]
	})
);

/* ---------------------------------------------------------- reading */

await store.write([
	row('tie-a', { accountId: 'bob', lastAt: at(100) }),
	row('tie-b', { accountId: 'bob', lastAt: at(100) }),
	row('tie-c', { accountId: 'bob', lastAt: at(100) }),
	row('older', {
		accountId: 'bob',
		lastAt: at(-100),
		kind: 'app',
		reason: 'not_in_group'
	})
]);
const first = await page('bob', 2);
const second = await store.listForPerson(bucketId, 'bob', {
	limit: 2,
	now: new Date(),
	...(first.next ? { before: first.next } : {})
});
check(
	'pages walk newest first, ties by id, without dropping or repeating a row',
	[...first.rows, ...second.rows].map((r) => r._id).join(',') ===
		'tie-c,tie-b,tie-a,older',
	[...first.rows, ...second.rows].map((r) => r._id).join(',')
);
const apps = await store.listForPerson(bucketId, 'bob', {
	kind: 'app',
	limit: 10,
	now: new Date()
});
check(
	'a kind filter reads only that kind',
	apps.rows.map((r) => r._id).join(',') === 'older'
);

const long = new Date(base.getTime() - 91 * DAY);
await store.write([row('expired', { accountId: 'carol', lastAt: long })]);
check(
	'a row past its expiry is never read',
	(await page('carol')).rows.length === 0
);

await store.write([
	row('overflow', { accountId: '*', reason: 'other', place: {} })
]);
check(
	'a day with an overflow row is found',
	(
		await store.overflowDays(
			bucketId,
			[base.toISOString().slice(0, 10), '2000-01-01'],
			new Date()
		)
	).join(',') === base.toISOString().slice(0, 10)
);

/* ---------------------------------------------------------- the expiry index */

async function expiryIndexed(): Promise<boolean> {
	if (mongo) {
		const { db } = await import('../lib/adapters/mongodb/db.js');
		const indexes = await db.collection(STORE_AREAS.personActivity).indexes();
		return indexes.some(
			(index) =>
				'expiresAt' in index.key && index.expireAfterSeconds !== undefined
		);
	}
	const { sql } = await import('../lib/adapters/postgres/index.js');
	const handle = sql();
	const rows = await handle<{ indexdef: string }[]>`
		SELECT indexdef FROM pg_indexes WHERE tablename = ${STORE_AREAS.personActivity}
	`;
	return rows.some((r) => r.indexdef.includes('expires_at'));
}
check('the area carries its expiry index', await expiryIndexed());

/* ---------------------------------------------------------- what a person used (specs/134) */

const used = (id: string, fields: Partial<Row> = {}): Row =>
	row(id, {
		accountId: 'carol',
		kind: 'api',
		outcome: 'let_in',
		reason: 'used',
		place: { resource: 'https://files.verify.test/mcp', clientId: 'agent' },
		...fields
	});
await store.write([used('tools', { tools: ['$where', 'read_file'] })]);
await store.write([
	used('tools', {
		tools: [
			'read_file',
			...Array.from(
				{ length: 25 },
				(_, i) => `tool_${String(i).padStart(2, '0')}`
			)
		]
	})
]);
const tooled = (await page('carol')).rows.find((r) => r._id === 'tools');
check(
	"an API row keeps the names it had, then new ones, at most twenty, a '$' name as written",
	JSON.stringify(tooled?.tools?.slice(0, 3)) ===
		JSON.stringify(['$where', 'read_file', 'tool_00']) &&
		tooled?.tools?.length === 20 &&
		tooled.count === 2,
	JSON.stringify(tooled?.tools)
);

/* Six five-minute writes of 2 000 people using two apps: one row a person and app, each with all its checks. */
const people = 2000;
const usedApps = ['wiki', 'files'];
const flushes = 6;
const started = Date.now();
for (let f = 0; f < flushes; f += 1) {
	const batch: Row[] = [];
	for (let p = 0; p < people; p += 1) {
		for (const app of usedApps) {
			batch.push(
				row(`use-${String(p)}-${app}`, {
					accountId: `user-${String(p)}`,
					kind: 'app',
					outcome: 'let_in',
					reason: 'used',
					place: { appId: app },
					count: 3,
					lastAt: at(f * 300)
				})
			);
		}
	}
	const { failed } = await store.write(batch);
	if (failed > 0) check('a use flush writes every row', false, `${failed}`);
}
const sample = await store.listForPerson(bucketId, 'user-1999', {
	limit: 10,
	now: new Date()
});
check(
	'a day of 2 000 people using two apps is one row a person and app, with every check added',
	sample.rows.length === 2 && sample.rows.every((r) => r.count === 3 * flushes),
	`${String(Math.round((Date.now() - started) / 1000))} s for ${String(people * usedApps.length * flushes)} writes`
);

await store.write([
	row('refused-now', { accountId: 'dave', lastAt: at(10) }),
	row('asked-now', {
		accountId: 'dave',
		kind: 'app',
		outcome: 'sign_in_again',
		reason: 'sign_in_again',
		place: { appId: 'wiki', rule: '/reports' },
		lastAt: at(20)
	}),
	row('refused-old', { accountId: 'dave', lastAt: at((-2 * DAY) / 1000) })
]);
const refusals = await store.listRefusals(bucketId, {
	since: new Date(base.getTime() - DAY),
	now: new Date(),
	limit: 100
});
check(
	'the refusals read sees the last day’s refusals and asks, never a use row or an older refusal',
	refusals.every((r) => r.outcome !== 'let_in') &&
		refusals.some((r) => r._id === 'refused-now') &&
		refusals.some((r) => r._id === 'asked-now') &&
		!refusals.some((r) => r._id === 'refused-old'),
	`${String(refusals.length)} rows`
);

async function indexed(area: string, fields: string[]): Promise<boolean> {
	if (mongo) {
		const { db } = await import('../lib/adapters/mongodb/db.js');
		const indexes = await db.collection(area).indexes();
		return indexes.some(
			(index) =>
				JSON.stringify(Object.keys(index.key)) === JSON.stringify(fields)
		);
	}
	const { sql } = await import('../lib/adapters/postgres/index.js');
	const handle = sql();
	const rows = await handle<{ indexdef: string }[]>`
		SELECT indexdef FROM pg_indexes WHERE tablename = ${area}
	`;
	return rows.some((r) => {
		const at = fields.map((field) => r.indexdef.indexOf(`'${field}'`));
		return at.every((i, n) => i >= 0 && (n === 0 || i > at[n - 1]));
	});
}
check(
	'the refusals index exists',
	await indexed(STORE_AREAS.personActivity, ['bucketId', 'outcome', 'lastAt'])
);
check(
	'the marks carry the account index the list of people reads',
	await indexed(STORE_AREAS.activityMarks, ['bucketId', 'accountId', 'period'])
);

/* ---------------------------------------------------------- Last active on the list of people (specs/134) */

const users = getUserStore(DEFAULT_BUCKET_ID);
const marks = getActivityStore();
const made: string[] = [];
const ages = [0, 10, 35, 130];
for (const [i, age] of ages.entries()) {
	const created = await users.create(
		`verify-active-${String(stamp)}-${String(i)}@verify.test`,
		'not-a-password',
		true
	);
	made.push(created._id);
	await marks.mark({
		bucketId: DEFAULT_BUCKET_ID,
		accountId: created._id,
		kind: 'renewal',
		provisioned: false,
		at: new Date(Date.now() - age * DAY)
	});
}
const never = await users.create(
	`verify-active-${String(stamp)}-never@verify.test`,
	'not-a-password',
	true
);
made.push(never._id);
type LastActive = import('../lib/adapters/types.js').LastActiveFilter;
const filtered = async (lastActive: LastActive): Promise<string> =>
	(
		await users.query(
			{ search: `verify-active-${String(stamp)}`, lastActive },
			{ startIndex: 1, count: 50 },
			'email'
		)
	).users
		.map((u) => made.indexOf(u._id))
		.filter((i) => i >= 0)
		.sort()
		.join(',');
const answers = [
	await filtered({ within: 7 }),
	await filtered({ within: 30 }),
	await filtered({ notWithin: 30 }),
	await filtered({ notWithin: 90 })
];
check(
	'each Last active filter returns exactly the people it names',
	answers.join(' | ') === '0 | 0,1 | 2,3,4 | 3,4',
	answers.join(' | ')
);
const latest = await marks.lastMarkedMany(DEFAULT_BUCKET_ID, made, new Date());
check(
	'the list’s Last active is the latest day, else the latest month, else nothing',
	'day' in (latest.get(made[0]) ?? {}) &&
		'day' in (latest.get(made[2]) ?? {}) &&
		'month' in (latest.get(made[3]) ?? {}) &&
		!latest.has(made[4])
);
for (const id of made) await users.destroy(id);

/* ---------------------------------------------------------- owner and location (spec 136) */

const MUNICH = {
	asn: 64500,
	asName: 'Example Net',
	regionCode: 'BY',
	region: 'Bavaria',
	city: 'Munich'
};
/* Compared with sorted keys: a jsonb column hands an object back with its keys reordered. */
function canonical(value: unknown): string {
	return JSON.stringify(value, (_key, inner: unknown) =>
		typeof inner === 'object' && inner !== null && !Array.isArray(inner)
			? Object.fromEntries(
					Object.entries(inner).sort(([a], [b]) => (a < b ? -1 : 1))
				)
			: inner
	);
}
const signInFrom = (address: string, lookup?: Row['lookup']): Row =>
	row('owner', {
		accountId: 'olga',
		method: 'password',
		address,
		addressFrom: 'sign_in',
		...(lookup === undefined ? {} : { lookup })
	});
const owner = async () =>
	(await page('olga')).rows.find((r) => r._id === 'owner');

await store.write([signInFrom('203.0.113.7', MUNICH)]);
check(
	'a row keeps the owner and location written with its address',
	canonical((await owner())?.lookup) === canonical(MUNICH),
	JSON.stringify((await owner())?.lookup)
);
await store.write([signInFrom('203.0.113.7')]);
check(
	'a write of the same address without a lookup keeps the one kept',
	canonical((await owner())?.lookup) === canonical(MUNICH)
);
await store.write([signInFrom('203.0.113.7', { asn: 64501 })]);
check(
	'a new lookup of the same address replaces the one kept',
	canonical((await owner())?.lookup) === canonical({ asn: 64501 })
);
await store.write([signInFrom('198.51.100.4')]);
const moved = await owner();
check(
	'a write of another address drops the owner and location of the old one',
	moved?.address === '198.51.100.4' && moved.lookup === undefined,
	JSON.stringify(moved?.lookup)
);
check(
	'rows with an address still add up and keep their method',
	moved?.count === 4 && moved.method === 'password',
	`${String(moved?.count)} ${String(moved?.method)}`
);

const { getTelemetryStateStore, instanceSigningKeyStore, foxtrustKeyStore } =
	await import('../lib/adapters/index.js');
const telemetry = getTelemetryStateStore();
await telemetry.instanceId();
/* The day after any an earlier run claimed in this database, so it never stands in the way. */
const claimedBefore = (await telemetry.read())?.registration?.lastClaimedDay;
const claimAt =
	claimedBefore === undefined
		? Date.UTC(3000, 0, 1)
		: new Date(`${claimedBefore}T00:00:00.000Z`).getTime() + DAY;
const claimDay = new Date(claimAt).toISOString().slice(0, 10);
const dayAfterClaim = new Date(claimAt + DAY).toISOString().slice(0, 10);
const claims = await Promise.all([
	telemetry.claimRegistrationDay(claimDay),
	telemetry.claimRegistrationDay(claimDay),
	telemetry.claimRegistrationDay(claimDay)
]);
check(
	'one registration day is claimed by exactly one of three racing processes',
	claims.filter(Boolean).length === 1,
	JSON.stringify(claims)
);
await Promise.all([
	telemetry.noteFirstKeyReport('2999-01-01T00:00:00.000Z'),
	telemetry.noteFirstKeyReport('2999-01-02T00:00:00.000Z')
]);
const firstNoted = (await telemetry.read())?.registration?.firstKeyReportAt;
await telemetry.noteFirstKeyReport('2999-01-03T00:00:00.000Z');
check(
	'the first report with the key is noted once and never moved',
	firstNoted !== undefined &&
		(await telemetry.read())?.registration?.firstKeyReportAt === firstNoted,
	String(firstNoted)
);
await telemetry.updateRegistration({ stopped: 'muted', notBefore: 'x' });
await telemetry.updateRegistration(
	{ lastAnswer: { at: 'y', outcome: 'key' } },
	['stopped', 'notBefore']
);
const registration = (await telemetry.read())?.registration;
check(
	'a registration update removes what it clears and keeps the rest',
	registration !== undefined &&
		registration.stopped === undefined &&
		registration.notBefore === undefined &&
		registration.lastAnswer?.outcome === 'key' &&
		registration.lastClaimedDay === claimDay,
	JSON.stringify(registration)
);
await telemetry.recordLookups({
	day: claimDay,
	at: 'a',
	exhaustedDay: claimDay
});
await telemetry.recordLookups({ day: claimDay, at: 'b', remaining: 3 });
const kept = (await telemetry.read())?.lookups;
check(
	'figures of the same day keep the day used up',
	kept?.exhaustedDay === claimDay && kept.remaining === 3,
	JSON.stringify(kept)
);
await telemetry.recordLookups({ day: dayAfterClaim, at: 'c', remaining: 9 });
check(
	'figures of the next day start without it',
	(await telemetry.read())?.lookups?.exhaustedDay === undefined
);
await telemetry.setLookupKey({
	receivedAt: 'r',
	dailyQuota: 1000,
	burst: 5
});
await telemetry.setLookupKey({ droppedAt: 'd' });
check(
	'a dropped key keeps when it was received',
	canonical((await telemetry.read())?.lookupKey) ===
		canonical({
			receivedAt: 'r',
			dailyQuota: 1000,
			burst: 5,
			droppedAt: 'd'
		}),
	JSON.stringify((await telemetry.read())?.lookupKey)
);

const pkcs8Sized = Buffer.from(Array.from({ length: 48 }, (_, i) => i));
const kept48 = await instanceSigningKeyStore.create(pkcs8Sized);
const read48 = await instanceSigningKeyStore.read();
check(
	'the instance key comes back as the same bytes',
	read48 instanceof Uint8Array &&
		Buffer.from(read48).equals(
			kept48 instanceof Uint8Array ? Buffer.from(kept48) : Buffer.alloc(0)
		)
);
const key = Buffer.from(`ftk_abcdefghijkl_${'K'.repeat(43)}`, 'utf8');
const storedKey =
	(await foxtrustKeyStore.read()) ?? (await foxtrustKeyStore.create(key));
check(
	'the FoxTrust key comes back as bytes',
	storedKey instanceof Uint8Array && storedKey.length > 0
);

/* ---------------------------------------------------------- an administrator's sign-in (spec 137) */

const { ADMIN_BUCKET_ID } = await import('../lib/admin/consts.js');
/* An account id no real administrator has, so the removal below can only take this script's row. */
const administrator = `verify-admin-${stamp}`;
await store.write([
	row('admin-sign-in', {
		bucketId: ADMIN_BUCKET_ID,
		accountId: administrator,
		outcome: 'let_in',
		reason: 'signed_in',
		place: { clientId: 'admin-panel' },
		method: 'password_code',
		address: '203.0.113.7',
		addressFrom: 'sign_in',
		lookup: MUNICH
	})
]);
const adminRow = (
	await store.listForPerson(ADMIN_BUCKET_ID, administrator, {
		limit: 5,
		now: new Date()
	})
).rows.at(0);
check(
	"an administrator's sign-in is kept in the administrators' project with its address and lookup",
	adminRow?.bucketId === ADMIN_BUCKET_ID &&
		adminRow.kind === 'signIn' &&
		adminRow.method === 'password_code' &&
		adminRow.address === '203.0.113.7' &&
		canonical(adminRow.lookup) === canonical(MUNICH),
	JSON.stringify(adminRow)
);
check(
	"an administrator's sign-in expires 90 days after it was written",
	adminRow?.expiresAt.getTime() === (adminRow?.lastAt.getTime() ?? 0) + 90 * DAY
);
await store.destroyPerson(ADMIN_BUCKET_ID, administrator);

/* ---------------------------------------------------------- an email about a new sign-in (spec 138) */

await store.write([
	row('alerted-sign-in', {
		accountId: 'alerted',
		outcome: 'let_in',
		reason: 'signed_in',
		method: 'password',
		address: '198.51.100.4',
		addressFrom: 'sign_in',
		alerted: 'both'
	})
]);
const alertedRow = (await page('alerted')).rows.at(0);
check(
	'a sign-in its owner was emailed about keeps why',
	alertedRow?.alerted === 'both',
	JSON.stringify(alertedRow?.alerted)
);
const { checkedAdapter } = await import('../lib/adapters/index.js');
const { SignInAlertClaimPayload } =
	await import('../lib/sign_in_alerts/types.js');
const alertClaims = checkedAdapter('SignInAlertClaim', SignInAlertClaimPayload);
const claimId = `verify-claim-${stamp}`;
const claimPayload = {
	accountId: 'alerted',
	exp: Math.floor(Date.now() / 1000) + 60
};
const firstClaim = await alertClaims.create(claimId, claimPayload, 60);
const secondClaim = await alertClaims.create(claimId, claimPayload, 60);
check(
	'a claim to email about a sign-in is taken once',
	firstClaim && !secondClaim,
	`${String(firstClaim)} ${String(secondClaim)}`
);
await alertClaims.destroy(claimId);

/* ---------------------------------------------------------- deletion */

await store.write([row('elsewhere', { bucketId: other })]);
const removed = await store.destroyPerson(bucketId, 'anna');
check(
	'deleting a person removes all their rows and nobody else’s',
	removed > 0 &&
		(await page()).rows.length === 0 &&
		(await page('bob')).rows.length === 4,
	`${removed}`
);
await store.destroyBucket(bucketId);
check(
	'destroying a project removes its rows and no other project’s',
	(await page('bob')).rows.length === 0 &&
		(await store.listForPerson(other, 'anna', { limit: 5, now: new Date() }))
			.rows.length === 1
);
await store.destroyBucket(other);

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
