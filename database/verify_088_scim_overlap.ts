/*
 * The specs/088 storage against a real datastore: a connection is found by its previous static token's digest
 * through the index `db:setup` builds for it, a credential's use is written into its own field only and the
 * current value's first use only once, two concurrent ends of a previous value act once, the holds read lists
 * exactly the held connections, a bucket's sign-in order reads back, and the static-token expiry migration
 * gives an expiry only to tokens without one and finds nothing the second time.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_088_scim_overlap.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_088_scim_overlap.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. Everything it writes belongs to ids unique to the run and is
 * removed at the end. It refuses a database whose name does not say it is disposable, as the other verify
 * scripts do.
 *
 * A script rather than a spec (Constitution Principle III): `bun test` runs the in-memory store, and what this
 * proves is that both real backends make each write one conditional statement and store nested dates as
 * dates — the connection document is a jsonb column in PostgreSQL and a document in MongoDB.
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
const { getBucketStore, getProvisioningConnectionStore } =
	await import('../lib/adapters/index.js');
const { STORE_AREAS } = await import('../lib/consts/storage_inventory.js');
const { MIGRATIONS } = await import('../lib/consts/migrations.js');
const { UNASSIGNED_GROUP_ID } = await import('../lib/admin/consts.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const DAY = 24 * 60 * 60 * 1000;
const stamp = `${Date.now()}`;
const bucketId = `v088-bucket-${stamp}`;
const store = getProvisioningConnectionStore();
const digest = (letter: string) => `${letter}${stamp}`.padEnd(64, letter);
const at = (minute: number) => new Date(Date.UTC(2026, 9, 12, 12, minute));

/* One half of the expiry migration, run on the selected backend's own handle. */
async function applyExpiryMigration(): Promise<unknown> {
	const migration = MIGRATIONS.find((m) =>
		m.id.endsWith('static-token-expiry')
	);
	if (!migration)
		throw new Error('the static-token expiry migration is not declared');
	const half = mongo ? migration.mongodb : migration.postgres;
	if ('noop' in half) throw new Error('the expiry migration has no step here');
	if (mongo) {
		const { db } = await import('../lib/adapters/mongodb/db.js');
		return half.apply(db);
	}
	const { sql } = await import('../lib/adapters/postgres/index.js');
	return half.apply(sql());
}

async function previousDigestIndexed(): Promise<boolean> {
	if (mongo) {
		const { db } = await import('../lib/adapters/mongodb/db.js');
		const indexes = await db
			.collection(STORE_AREAS.provisioningConnections)
			.indexes();
		return indexes.some((index) => 'previousStaticToken.digest' in index.key);
	}
	const { sql } = await import('../lib/adapters/postgres/index.js');
	const handle = sql();
	const rows = await handle<{ indexdef: string }[]>`
		SELECT indexdef FROM pg_indexes
		WHERE tablename = ${STORE_AREAS.provisioningConnections}
	`;
	return rows.some((row) => row.indexdef.includes("'previousStaticToken'"));
}

function base(id: string, providerId: string) {
	return {
		_id: id,
		bucketId,
		displayName: `Directory ${id}`,
		enabled: true,
		providerId,
		correlation: {
			claim: 'preferred_username',
			attribute: 'userName' as const
		},
		emailTrust: 'untrusted' as const
	};
}

const ids = {
	token: `v088-token-${stamp}`,
	secret: `v088-secret-${stamp}`,
	old: `v088-old-${stamp}`,
	young: `v088-young-${stamp}`,
	dated: `v088-dated-${stamp}`
};

try {
	check(
		'db:setup built an index on the previous static token’s digest',
		await previousDigestIndexed()
	);

	await store.create({
		...base(ids.token, 'p-token'),
		oauthCredential: null,
		staticTokenDigest: digest('a'),
		staticTokenIssuedAt: at(0),
		staticTokenExpiresAt: new Date(at(0).getTime() + 365 * DAY),
		previousStaticToken: {
			digest: digest('b'),
			issuedAt: at(0),
			replacedAt: at(1),
			expiresAt: new Date(at(0).getTime() + 90 * DAY)
		}
	});
	await store.create({
		...base(ids.secret, 'p-secret'),
		oauthCredential: { kind: 'secret', digest: digest('c'), issuedAt: at(0) },
		previousSecret: { digest: digest('d'), issuedAt: at(0), replacedAt: at(2) }
	});

	const byPrevious = await store.findByPreviousStaticTokenDigest(digest('b'));
	check(
		'a connection is found by its previous static token’s digest',
		byPrevious?._id === ids.token
	);
	check(
		'the previous static token reads back with its dates as dates',
		byPrevious?.previousStaticToken?.replacedAt instanceof Date &&
			byPrevious.previousStaticToken.expiresAt instanceof Date
	);
	check(
		'a previous digest is not taken for a current one',
		(await store.findByStaticTokenDigest(digest('b'))) === null
	);

	await store.noteCredentialUse(ids.secret, 'secret', 'current', at(5));
	await store.noteCredentialUse(ids.secret, 'secret', 'current', at(9));
	const secretUsed = await store.find(ids.secret);
	check(
		'the current secret’s first use is written once',
		secretUsed?.oauthCredential?.kind === 'secret' &&
			secretUsed.oauthCredential.firstUsedAt?.getTime() === at(5).getTime()
	);

	await store.noteCredentialUse(ids.token, 'static_token', 'current', at(6));
	await store.noteCredentialUse(ids.token, 'static_token', 'current', at(7));
	check(
		'the current static token’s first use is written once',
		(await store.find(ids.token))?.staticTokenFirstUsedAt?.getTime() ===
			at(6).getTime()
	);

	await store.noteCredentialUse(ids.secret, 'secret', 'previous', at(10));
	await store.noteCredentialUse(ids.secret, 'secret', 'previous', at(11));
	const previousUsed = await store.find(ids.secret);
	check(
		'a previous secret’s last use moves and the current secret is untouched',
		previousUsed?.previousSecret?.lastUsedAt?.getTime() === at(11).getTime() &&
			previousUsed.oauthCredential?.kind === 'secret' &&
			previousUsed.oauthCredential.digest === digest('c')
	);

	await store.noteCredentialUse(ids.token, 'secret', 'previous', at(12));
	check(
		'a use of a previous value a slot does not hold writes nothing',
		(await store.find(ids.token))?.previousSecret === undefined
	);

	check(
		'a previous value is not ended for a digest that is no longer its',
		!(await store.retirePrevious(ids.secret, 'secret', digest('e'))) &&
			(await store.find(ids.secret))?.previousSecret?.digest === digest('d')
	);
	const ends = await Promise.all([
		store.retirePrevious(ids.secret, 'secret', digest('d')),
		store.retirePrevious(ids.secret, 'secret', digest('d'))
	]);
	check(
		'two concurrent ends of one previous value act once',
		ends.filter(Boolean).length === 1,
		JSON.stringify(ends)
	);
	check(
		'the ended previous value is gone',
		(await store.find(ids.secret))?.previousSecret === undefined
	);

	await store.holdIfFree(ids.secret, { since: at(20), count: 4 });
	const held = (await store.listHeld()).filter((c) => c.bucketId === bucketId);
	check(
		'the holds read lists the held connection and no other',
		held.length === 1 &&
			held[0]?._id === ids.secret &&
			held[0].hold.since instanceof Date &&
			held[0].hold.count === 4,
		JSON.stringify(held)
	);

	const bucket = await getBucketStore().create({
		_id: bucketId,
		name: `v088 ${stamp}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	await getBucketStore().update(bucket._id, { signInOrder: ['b', 'a'] });
	await getBucketStore().update(bucket._id, { federation: [] });
	check(
		'a bucket’s sign-in order reads back, and survives a provider write',
		JSON.stringify((await getBucketStore().find(bucket._id))?.signInOrder) ===
			JSON.stringify(['b', 'a'])
	);

	const now = Date.now();
	await store.create({
		...base(ids.old, 'p-old'),
		oauthCredential: null,
		staticTokenDigest: digest('f'),
		staticTokenIssuedAt: new Date(now - 730 * DAY)
	});
	const youngIssued = new Date(now - 30 * DAY);
	await store.create({
		...base(ids.young, 'p-young'),
		oauthCredential: null,
		staticTokenDigest: digest('g'),
		staticTokenIssuedAt: youngIssued
	});
	const datedExpiry = new Date(now + 5 * DAY);
	await store.create({
		...base(ids.dated, 'p-dated'),
		oauthCredential: null,
		staticTokenDigest: digest('h'),
		staticTokenIssuedAt: new Date(now - 400 * DAY),
		staticTokenExpiresAt: datedExpiry
	});

	const first = await applyExpiryMigration();
	const oldExpiry = (await store.find(ids.old))?.staticTokenExpiresAt;
	check(
		'the migration gives a two-year-old token 90 days from now',
		oldExpiry !== undefined &&
			Math.abs(oldExpiry.getTime() - (now + 90 * DAY)) < 5 * 60 * 1000,
		oldExpiry?.toISOString()
	);
	check(
		'the migration gives a month-old token a year from its issue',
		(await store.find(ids.young))?.staticTokenExpiresAt?.getTime() ===
			youngIssued.getTime() + 365 * DAY
	);
	check(
		'the migration leaves a token that already expires',
		(await store.find(ids.dated))?.staticTokenExpiresAt?.getTime() ===
			datedExpiry.getTime()
	);
	const second = await applyExpiryMigration();
	check(
		'the migration finds nothing the second time',
		JSON.stringify(second) ===
			JSON.stringify(['static tokens given an expiry: 0']) &&
			(await store.find(ids.old))?.staticTokenExpiresAt?.getTime() ===
				oldExpiry?.getTime(),
		`${JSON.stringify(first)} then ${JSON.stringify(second)}`
	);
} finally {
	await store.destroyByBucket(bucketId);
	await getBucketStore().destroy(bucketId);
}

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
