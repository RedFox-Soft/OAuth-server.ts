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
const { getPersonActivityStore } = await import('../lib/adapters/index.js');
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
