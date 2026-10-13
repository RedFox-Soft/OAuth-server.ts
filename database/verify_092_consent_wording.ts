/*
 * The specs/092 storage against a real datastore: a bucket's name for its people is written, read back and
 * removed again by an update that names it with no value, and a declared resource keeps its scope
 * descriptions as a nested map with no member stored as null.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_092_consent_wording.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_092_consent_wording.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. Everything it writes belongs to ids unique to the run and is
 * removed at the end. It refuses a database whose name does not say it is disposable, as the other verify
 * scripts do.
 *
 * A script rather than a spec (Constitution Principle III): `bun test` runs the in-memory store, whose
 * update removes a field by deleting a property. What this proves is that MongoDB's `$unset` and
 * PostgreSQL's `doc - key` do the same — a merge alone would leave the old name on every end-user page.
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
const { getBucketStore, getProtectedResourceStore } =
	await import('../lib/adapters/index.js');
const { UNASSIGNED_GROUP_ID } = await import('../lib/admin/consts.js');

/* PostgreSQL's jsonb stores an object's keys in its own order, so equality is compared key by key. */
function canonical(value: unknown): string {
	return JSON.stringify(value, (_key, v: unknown) =>
		v && typeof v === 'object' && !Array.isArray(v)
			? Object.fromEntries(
					Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
						a.localeCompare(b)
					)
				)
			: v
	);
}

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const stamp = `${Date.now()}`;
const bucketId = `v092-bucket-${stamp}`;
const namespace = `v092-namespace-${stamp}`;
const identifier = `https://v092-${stamp}.example.com/mcp`;

try {
	await getBucketStore().create({
		_id: bucketId,
		name: 'v092 users',
		displayName: 'Acme ID',
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	check(
		'a bucket keeps the name shown to its people',
		(await getBucketStore().find(bucketId))?.displayName === 'Acme ID'
	);

	await getBucketStore().update(bucketId, { displayName: 'Acme Accounts' });
	check(
		'an update replaces the name shown to its people',
		(await getBucketStore().find(bucketId))?.displayName === 'Acme Accounts'
	);

	await getBucketStore().update(bucketId, { displayName: undefined });
	const cleared = await getBucketStore().find(bucketId);
	check(
		'an update naming it with no value removes it',
		cleared !== null && !('displayName' in cleared),
		JSON.stringify(cleared?.displayName)
	);
	check(
		'removing it leaves the rest of the bucket as it was',
		cleared?.name === 'v092 users'
	);

	await getProtectedResourceStore().create({
		namespace,
		identifier,
		projectId: `v092-project-${stamp}`,
		name: 'v092 MCP',
		scopes: ['tools:read', 'tools:call'],
		scopeDescriptions: {
			'tools:read': { description: 'see the tools', kind: 'see' },
			'tools:call': { description: 'run the tools as you' }
		}
	});
	const declared = await getProtectedResourceStore().find(
		namespace,
		identifier
	);
	check(
		'a resource keeps its scope descriptions, with no member stored as null',
		canonical(declared?.scopeDescriptions) ===
			canonical({
				'tools:read': { description: 'see the tools', kind: 'see' },
				'tools:call': { description: 'run the tools as you' }
			}),
		JSON.stringify(declared?.scopeDescriptions)
	);

	await getProtectedResourceStore().update(namespace, identifier, {
		scopes: ['tools:read'],
		scopeDescriptions: {
			'tools:read': { description: 'see the tools', kind: 'see' }
		}
	});
	check(
		'an update replaces the descriptions whole',
		canonical(
			(await getProtectedResourceStore().find(namespace, identifier))
				?.scopeDescriptions
		) ===
			canonical({
				'tools:read': { description: 'see the tools', kind: 'see' }
			})
	);
} finally {
	await getProtectedResourceStore().destroy(namespace, identifier);
	await getBucketStore().destroy(bucketId);
}

console.log(failures === 0 ? 'all checks passed' : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
