/*
 * The specs/087 key state against a real datastore: a key set to `revoked` reads back as revoked, the issuer's
 * assembled key set leaves it out of what it publishes, verifies and signs with, revoking a signer with no
 * ready key leaves the algorithm signed by a newly created key, and an audit entry's `keys` map reads back.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_087_revoked_state.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_087_revoked_state.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. The keys it writes belong to an owner unique to the run and are
 * removed at the end; the audit entry stays, since the trail is append-only. It refuses a database whose name
 * does not say it is disposable, as the other verify scripts do.
 *
 * A script rather than a spec (Constitution Principle III): `bun test` runs the in-memory store, and what this
 * proves is that both real backends store the widened state as written and read it back — the key document is
 * a jsonb column in PostgreSQL and a document in MongoDB, and neither may have kept an older shape's check.
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
const { adminAuditStore, getBucketKeysStore } =
	await import('../lib/adapters/index.js');
const { generateJWKS } = await import('../lib/helpers/jwks.js');
const { keysFor, invalidateBucketKeys } =
	await import('../lib/keys/issuer_keys.js');
const lifecycle = await import('../lib/admin/key_lifecycle.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const stamp = `${Date.now()}`;
const owner = `v087-bucket-${stamp}`;
const bucket = { _id: owner, slug: `v087-${stamp}` };
const store = getBucketKeysStore();

async function key(state: 'signing' | 'published', at: Date) {
	const {
		keys: [jwk]
	} = await generateJWKS('RS256');
	await store.createIfAbsent({
		_id: `${owner} ${jwk.kid}`,
		bucketId: owner,
		kid: jwk.kid,
		jwk,
		alg: 'RS256',
		use: 'sig',
		state,
		createdAt: at,
		stateChangedAt: at
	});
	return jwk.kid;
}

const kidsOf = (keyStore: Iterable<{ kid?: unknown }>) =>
	[...keyStore].map((entry) => String(entry.kid));

try {
	/* Past the publication window, so the published key would be ready — revoked, it must not be. */
	const long = new Date(Date.now() - 3600_000);
	const signer = await key('signing', long);
	const published = await key('published', long);

	const revoked = await store.setState(owner, published, 'revoked', new Date());
	check(
		'setState writes revoked and answers the record',
		revoked?.state === 'revoked',
		String(revoked?.state)
	);
	check(
		'find reads a revoked key back as revoked',
		(await store.find(owner, published))?.state === 'revoked'
	);
	check(
		'listByBucket keeps the revoked record',
		(await store.listByBucket(owner)).some(
			(entry) => entry.kid === published && entry.state === 'revoked'
		)
	);

	invalidateBucketKeys(owner);
	const assembled = await keysFor(bucket);
	check(
		'the issuer key set publishes no revoked key',
		!assembled.publicJWKS.keys.some((entry) => entry.kid === published) &&
			assembled.publicJWKS.keys.some((entry) => entry.kid === signer),
		assembled.publicJWKS.keys.map((entry) => entry.kid).join(', ')
	);
	check(
		'the issuer verifies with no revoked key',
		!kidsOf(assembled.verification).includes(published)
	);

	const audited: Array<Record<string, string> | undefined> = [];
	const keyOwner = {
		id: owner,
		audit: async (
			_verb: string,
			_kid: string,
			keys?: Record<string, string>
		) => {
			audited.push(keys);
		},
		invalidate: () => invalidateBucketKeys(owner)
	};

	const listed = await lifecycle.listKeys(keyOwner);
	check(
		'the key list leaves a revoked key out',
		!listed.keys.some((entry) => entry.kid === published)
	);

	const outcome = await lifecycle.revokeKey(keyOwner, signer, signer);
	const replacement = outcome.replacement ?? '';
	check(
		'revoking the signer with no ready key creates a key that signs at once',
		outcome.replacementGenerated &&
			(await store.find(owner, replacement))?.state === 'signing',
		JSON.stringify(outcome)
	);
	check(
		'the revoked signer reads back as revoked',
		(await store.find(owner, signer))?.state === 'revoked'
	);
	const after = await keysFor(bucket);
	check(
		'the issuer signs with the replacement and with neither revoked key',
		JSON.stringify(kidsOf(after.signing)) === JSON.stringify([replacement]) &&
			!kidsOf(after.verification).some((kid) =>
				[signer, published].includes(kid)
			),
		kidsOf(after.verification).join(', ')
	);

	const entry = await adminAuditStore.record({
		actorId: `v087-admin-${stamp}`,
		actorEmail: `v087-${stamp}@verify.test`,
		action: 'bucket.key.revoke',
		targetType: 'UserBucket',
		targetId: owner,
		kid: signer,
		keys: { revoked: signer, signing: replacement, generated: replacement }
	});
	const read = (
		await adminAuditStore.list({ targetId: owner, action: 'bucket.key.revoke' })
	).entries.find((candidate) => candidate._id === entry._id);
	// Compared by entries, sorted: jsonb does not keep the order an object's keys were written in.
	const entries = (map: Record<string, string> | null | undefined) =>
		JSON.stringify(Object.entries(map ?? {}).sort());
	check(
		'an audit entry reads back with its keys map',
		entries(read?.keys) ===
			entries({
				revoked: signer,
				signing: replacement,
				generated: replacement
			}),
		JSON.stringify(read?.keys)
	);
} finally {
	await store.destroyByBucket(owner);
}

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
