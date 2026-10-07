/*
 * The mass-deprovisioning guard's concurrency properties against a real datastore (specs/072 FR-019, SC-004).
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_deprovision_guard.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_deprovision_guard.ts
 *
 * Run once per backend; it uses whichever one connection string names, and refuses both. DESTRUCTIVE in the
 * way the other verify scripts are — it writes connections, tally records and audit entries — so it refuses a
 * database whose name does not say it is disposable.
 *
 * A script rather than a spec (Constitution Principle III): the in-memory store serialises racing callers by
 * having no `await` between a read and a write, so `bun test` proves the arithmetic of the slot ring but cannot
 * prove that `holdIfFree`, `create` and `increment` are single atomic writes on MongoDB and PostgreSQL — which
 * is the whole of the guard's exactness under concurrency.
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
const { admitDeprovisioning } =
	await import('../lib/provisioning/deprovision_guard.js');
const { ScimError } = await import('../lib/scim/errors.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const store = getProvisioningConnectionStore();
const stamp = Date.now();
const bucketId = `verify-guard-bucket-${stamp}`;
const connectionOf = (id: string, providerId: string) => ({
	_id: `${id}-${stamp}`,
	bucketId,
	displayName: id,
	enabled: true,
	providerId,
	correlation: { claim: 'oid', attribute: 'externalId' as const },
	emailTrust: 'untrusted' as const,
	oauthCredential: null
});

console.log(
	`verifying the deprovisioning guard on ${mongo ? 'MongoDB' : 'PostgreSQL'}`
);

const racing = await store.create(connectionOf('hold-race', 'race'));
const told = await Promise.all(
	Array.from({ length: 20 }, () =>
		store.holdIfFree(racing._id, { since: new Date(), count: 7 })
	)
);
check(
	'20 concurrent holds of one connection: exactly one is told it set the hold',
	told.filter(Boolean).length === 1,
	`${told.filter(Boolean).length} told true`
);

const unheld = await store.create(connectionOf('unheld', 'unheld'));
const notReleased = await store.releaseHold(unheld._id);
check(
	'releasing a connection that is not held answers null',
	notReleased === null,
	String(notReleased?._id)
);

const released = await store.releaseHold(racing._id);
check(
	'releasing a held connection clears the hold and moves the tally epoch on',
	released !== null && released.hold === undefined && released.tallyEpoch === 1,
	JSON.stringify({ hold: released?.hold, tallyEpoch: released?.tallyEpoch })
);
const reread = await store.find(racing._id);
check(
	'the release is stored, not only answered',
	reread !== null && reread.hold === undefined && reread.tallyEpoch === 1
);

const guarded = await store.create({
	...connectionOf('claims', 'claims'),
	threshold: { count: 10, windowSeconds: 3600 }
});
/* Owned by a group nobody belongs to, so the hold's alert has no recipient and sends nothing. */
const bucket = await getBucketStore().create({
	_id: bucketId,
	name: `verify-guard-${stamp}`,
	ownerGroupId: `verify-group-${stamp}`
});
const claims = await Promise.allSettled(
	Array.from({ length: 100 }, () => admitDeprovisioning(bucket, guarded))
);
const admitted = claims.filter((c) => c.status === 'fulfilled').length;
const held = claims.filter(
	(c) =>
		c.status === 'rejected' &&
		c.reason instanceof ScimError &&
		c.reason.status === 429
).length;
check(
	'100 concurrent deprovisionings against a threshold of 10: exactly 10 are admitted',
	admitted === 10,
	`${admitted} admitted`
);
check(
	'every other one is refused with the retryable 429, and nothing fails otherwise',
	held === 90,
	`${held} refused with 429`
);
check(
	'the connection is left held',
	(await store.find(guarded._id))?.hold !== undefined
);

await store.destroyByBucket(bucketId);
await getBucketStore().destroy(bucketId);

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
