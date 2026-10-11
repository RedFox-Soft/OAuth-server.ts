/*
 * The two datastore additions of specs/084 against a real datastore: the record of removals a held provisioning
 * connection was refused, and the count of accounts linked to a provider.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_084_refusals.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_084_refusals.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. It writes and then removes its own records, and refuses a database
 * whose name does not say it is disposable, as the other verify scripts do.
 *
 * A script rather than a spec (Constitution Principle III): the in-memory store serialises racing notes by
 * having no `await` inside one, so `bun test` cannot prove that a note is one atomic upsert on MongoDB and
 * PostgreSQL — which is what keeps every retry of a held directory counted.
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
const { getBucketStore, getProvisioningRefusalStore, getUserStore } =
	await import('../lib/adapters/index.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const stamp = Date.now();
const bucketId = `verify-084-${stamp}`;
const connectionId = `verify-084-conn-${stamp}`;
const other = `verify-084-other-${stamp}`;
const refusals = getProvisioningRefusalStore();
const base = new Date();
const at = (seconds: number) => new Date(base.getTime() + seconds * 1000);

/* ---------------------------------------------------------- refusals */

await Promise.all(
	Array.from({ length: 50 }, (_, i) =>
		refusals.note({
			connectionId,
			bucketId,
			epoch: 0,
			userId: 'racing',
			operation: i % 2 === 0 ? 'deactivate' : 'delete',
			at: at(i)
		})
	)
);
const raced = await refusals.list(connectionId, 0, 10);
check(
	'fifty concurrent refusals of one person leave one record counting all fifty',
	raced.total === 1 && raced.refusals[0]?.attempts === 50,
	JSON.stringify({
		total: raced.total,
		attempts: raced.refusals[0]?.attempts
	})
);
check(
	'the record keeps the latest attempt time whatever order the writes landed in',
	raced.refusals[0]?.lastAt.getTime() === at(49).getTime(),
	raced.refusals[0]?.lastAt.toISOString() ?? 'no record'
);
check(
	'its times are read back as dates',
	raced.refusals[0]?.firstAt instanceof Date &&
		raced.refusals[0]?.lastAt instanceof Date
);

await refusals.note({
	connectionId,
	bucketId,
	epoch: 0,
	userId: 'early',
	operation: 'delete',
	at: at(-100)
});
await refusals.note({
	connectionId,
	bucketId,
	epoch: 0,
	userId: 'latest',
	operation: 'deactivate',
	at: at(100)
});
const listed = await refusals.list(connectionId, 0, 2);
check(
	'the list is most recent first and stops at the limit, with the full total',
	listed.refusals.map((r) => r.userId).join(',') === 'latest,racing' &&
		listed.total === 3,
	`${listed.refusals.map((r) => r.userId).join(',')} of ${listed.total}`
);
const counted = await refusals.list(connectionId, 0, 0);
check(
	'a count-only read returns the total and no rows',
	counted.refusals.length === 0 && counted.total === 3,
	JSON.stringify({ rows: counted.refusals.length, total: counted.total })
);

await refusals.note({
	connectionId,
	bucketId,
	epoch: 1,
	userId: 'racing',
	operation: 'deactivate',
	at: at(200)
});
const next = await refusals.list(connectionId, 1, 10);
check(
	'the next hold generation starts the same person afresh',
	next.total === 1 && next.refusals[0]?.attempts === 1
);

await refusals.note({
	connectionId: other,
	bucketId,
	epoch: 0,
	userId: 'elsewhere',
	operation: 'delete',
	at: at(0)
});
check(
	'destroying one connection’s records takes every generation of it and nothing else',
	(await refusals.destroyByConnection(connectionId)) === 4 &&
		(await refusals.list(connectionId, 1, 10)).total === 0 &&
		(await refusals.list(other, 0, 10)).total === 1
);
check(
	'destroying a bucket’s records takes the rest',
	(await refusals.destroyByBucket(bucketId)) === 1 &&
		(await refusals.list(other, 0, 10)).total === 0
);

/* ---------------------------------------------------------- linked count */

await getBucketStore().create({
	_id: bucketId,
	name: `verify-084-${stamp}`,
	ownerGroupId: `verify-group-${stamp}`
});
const users = getUserStore(bucketId);
const link = (providerId: string, sub: string) => ({
	providerId,
	sub,
	linkedAt: new Date()
});
const both = await users.create(`both-${stamp}@acme.test`, 'hash', true);
await users.update(both._id, {
	federated: [link('acme', 'a-1'), link('other', 'o-1')]
});
const twice = await users.create(`twice-${stamp}@acme.test`, 'hash', true);
await users.update(twice._id, {
	federated: [link('acme', 'a-2'), link('acme', 'a-3')]
});
const elsewhere = await users.create(
	`elsewhere-${stamp}@acme.test`,
	'hash',
	true
);
await users.update(elsewhere._id, { federated: [link('other', 'o-2')] });
await users.create(`password-${stamp}@acme.test`, 'hash', true);

const linked = await users.countLinkedTo('acme');
check(
	'the linked count counts each account linked to the provider once, and nobody else',
	linked === 2,
	`${linked}`
);
check(
	'the linked count agrees with the linked list',
	linked === (await users.findLinkedTo('acme')).length
);
check(
	'a provider nobody is linked to counts zero',
	(await users.countLinkedTo('nobody')) === 0
);

for (const user of await users.list()) await users.destroy(user._id);
await users.destroyArea();
await getBucketStore().destroy(bucketId);

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
