/*
 * The audit trail's specs/085 additions against a real datastore: the `bucket`, `connection` and `actionPrefix`
 * filters, the entry fields they read (`bucketId`, `formerBucketId`) and `kid`, and the two indexes the bucket
 * filter's new arms ride on.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_085_audit_filters.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_085_audit_filters.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. The trail is append-only, so the entries it writes stay: each
 * names identifiers unique to the run, which is what keeps one run's checks blind to another's. It refuses a
 * database whose name does not say it is disposable, as the other verify scripts do.
 *
 * A script rather than a spec (Constitution Principle III): `bun test` runs the in-memory matcher, and what
 * this proves is that MongoDB's query document and PostgreSQL's WHERE clause agree with it — the escaping of
 * a prefix above all, which the in-memory `startsWith` gets right for free.
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
const { adminAuditStore } = await import('../lib/adapters/index.js');
const { STORE_AREAS, areaNamed } =
	await import('../lib/consts/storage_inventory.js');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const stamp = `${Date.now()}`;
const bucket = `v085-bucket-${stamp}`;
const other = `v085-other-${stamp}`;
const connection = `v085-conn-${stamp}`;
const project = `v085-project-${stamp}`;
const group = `v085-group-${stamp}`;
const foreignGroup = `v085-foreign-${stamp}`;
const kid = `v085-kid-${stamp}`;

const base = {
	actorId: `v085-admin-${stamp}`,
	actorEmail: `v085-${stamp}@verify.test`,
	ownerGroupId: group
};

/* One entry per way an action can belong to the bucket, and one of each that must not. */
const written = {
	settings: await adminAuditStore.record({
		...base,
		action: 'bucket.update',
		targetType: 'UserBucket',
		targetId: bucket,
		attributes: ['name']
	}),
	key: await adminAuditStore.record({
		...base,
		action: 'bucket.key.generate',
		targetType: 'UserBucket',
		targetId: bucket,
		kid
	}),
	person: await adminAuditStore.record({
		...base,
		action: 'enduser.create',
		targetType: 'EndUser',
		targetId: `v085-user-${stamp}`,
		targetScope: bucket
	}),
	joined: await adminAuditStore.record({
		...base,
		action: 'project.bucket.assign',
		targetType: 'Project',
		targetId: project,
		bucketId: bucket,
		formerBucketId: other,
		attributes: ['bucketId']
	}),
	left: await adminAuditStore.record({
		...base,
		action: 'project.bucket.clear',
		targetType: 'Project',
		targetId: project,
		formerBucketId: bucket
	}),
	connectionCreated: await adminAuditStore.record({
		...base,
		action: 'provisioning.connection.create',
		targetType: 'ProvisioningConnection',
		targetId: connection,
		targetScope: other
	}),
	byDirectory: await adminAuditStore.record({
		actorId: `connection:${connection}`,
		actorEmail: `connection:${connection}`,
		action: 'enduser.update',
		targetType: 'EndUser',
		targetId: `v085-synced-${stamp}`,
		targetScope: other,
		ownerGroupId: group,
		viaSurface: 'scim'
	}),
	elsewhere: await adminAuditStore.record({
		...base,
		action: 'bucket.update',
		targetType: 'UserBucket',
		targetId: other
	}),
	/* A bucket id in a field the filter does not read: an entry about something else, not about the bucket. */
	unrelated: await adminAuditStore.record({
		...base,
		action: 'client.update',
		targetType: 'Client',
		targetId: bucket
	}),
	foreign: await adminAuditStore.record({
		...base,
		ownerGroupId: foreignGroup,
		action: 'bucket.update',
		targetType: 'UserBucket',
		targetId: bucket
	})
};

const ids = (entries: { _id: string }[]) =>
	entries.map((entry) => entry._id).sort();
const expected = (...entries: { _id: string }[]) => ids(entries);

const byBucket = await adminAuditStore.list({ bucket, limit: 200 });
check(
	'bucket finds the bucket as target, a target within it, and a project joining and leaving it',
	JSON.stringify(ids(byBucket.entries)) ===
		JSON.stringify(
			expected(
				written.settings,
				written.key,
				written.person,
				written.joined,
				written.left,
				written.foreign
			)
		) && byBucket.total === 6,
	`${byBucket.total} entries`
);

const formerOnly = await adminAuditStore.list({ bucket: other, limit: 200 });
check(
	'bucket finds a project that left it through formerBucketId alone',
	ids(formerOnly.entries).includes(written.joined._id) &&
		JSON.stringify(ids(formerOnly.entries)) ===
			JSON.stringify(
				expected(
					written.joined,
					written.connectionCreated,
					written.byDirectory,
					written.elsewhere
				)
			),
	`${formerOnly.total} entries`
);

const scoped = await adminAuditStore.list({
	bucket,
	ownerGroupIds: [group],
	limit: 200
});
check(
	'bucket never widens the group boundary',
	!ids(scoped.entries).includes(written.foreign._id) && scoped.total === 5,
	`${scoped.total} entries`
);

const outsider = await adminAuditStore.list({
	bucket,
	ownerGroupIds: [`v085-nobody-${stamp}`]
});
check(
	'bucket returns nothing to a caller in none of its groups',
	outsider.total === 0
);

const byConnection = await adminAuditStore.list({ connection, limit: 200 });
check(
	'connection finds what the directory did and what was done to it',
	JSON.stringify(ids(byConnection.entries)) ===
		JSON.stringify(expected(written.connectionCreated, written.byDirectory)),
	`${byConnection.total} entries`
);

const byActorAndConnection = await adminAuditStore.list({
	connection,
	actor: base.actorId,
	limit: 200
});
check(
	'connection is ANDed with the actor filter, each a disjunction of its own',
	JSON.stringify(ids(byActorAndConnection.entries)) ===
		JSON.stringify(expected(written.connectionCreated)),
	`${byActorAndConnection.total} entries`
);

const keyed = await adminAuditStore.list({
	bucket,
	actionPrefix: 'bucket.key.',
	limit: 200
});
check(
	'actionPrefix finds actions starting with the text',
	JSON.stringify(ids(keyed.entries)) === JSON.stringify(expected(written.key))
);
check(
	'an entry carries the kid it was written with',
	keyed.entries.at(0)?.kid === kid,
	String(keyed.entries.at(0)?.kid)
);

for (const literal of [
	'bucket_key',
	'bucket%',
	'bucket.ke.',
	'.*',
	'^bucket'
]) {
	const matched = await adminAuditStore.list({
		bucket,
		actionPrefix: literal
	});
	check(
		`actionPrefix '${literal}' is read as text, not as a pattern`,
		matched.total === 0,
		`${matched.total} entries`
	);
}

const exactAndPrefix = await adminAuditStore.list({
	bucket,
	action: 'bucket.update',
	actionPrefix: 'bucket.key.'
});
check(
	'actionPrefix narrows an exact action rather than replacing it',
	exactAndPrefix.total === 0
);

const joined = (
	await adminAuditStore.list({
		targetId: project,
		action: 'project.bucket.assign'
	})
).entries.at(0);
check(
	'a project bucket change reads back with both bucket fields',
	joined?.bucketId === bucket && joined.formerBucketId === other,
	JSON.stringify({
		bucketId: joined?.bucketId,
		formerBucketId: joined?.formerBucketId
	})
);

/* ---------------------------------------------------------- indexes */

const declared = [
	{ bucketId: 1, timestamp: 1 },
	{ formerBucketId: 1, timestamp: 1 }
];
if (mongo) {
	const { db } = await import('../lib/adapters/mongodb/db.js');
	const keys = (await db.collection(STORE_AREAS.adminAudit).indexes()).map(
		(index) => JSON.stringify(index.key)
	);
	check(
		'db:setup provisioned the bucket filter indexes',
		declared.every((key) => keys.includes(JSON.stringify(key))),
		keys.join(', ')
	);
} else {
	const { indexStatements, sql } =
		await import('../lib/adapters/postgres/index.js');
	const area = areaNamed(STORE_AREAS.adminAudit);
	const handle = sql();
	const present = new Set(
		(
			await handle<{ indexname: string }[]>`
				SELECT indexname FROM pg_indexes WHERE tablename = ${area.name}
			`
		).map((row) => row.indexname)
	);
	const planned = indexStatements(area).filter(
		(index) =>
			index.statement.includes("'bucketId'") ||
			index.statement.includes("'formerBucketId'")
	);
	check(
		'db:setup:pg provisioned the bucket filter indexes',
		planned.length === 2 && planned.every((index) => present.has(index.name)),
		[...present].join(', ')
	);
}

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
