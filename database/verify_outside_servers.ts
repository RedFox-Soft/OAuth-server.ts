import type {
	OutsideAuthorizationServer,
	OutsideAuthorizationServerStoreInstance
} from '../lib/adapters/types.js';
import { outsideServerId } from '../lib/assertions/outside_server_id.js';

/* By name rather than by class, for the reason verify_provisioning_connections.ts gives. */
function isTaken(error: unknown): boolean {
	return error instanceof Error && error.name === 'UniqueValueTaken';
}

/* What the AssertionUsage model area is reached through: the generic model adapter, on either backend. */
interface UsageArea {
	upsert(id: string, payload: { lastUsedAt: number }): Promise<void>;
	find(id: string): Promise<{ lastUsedAt?: unknown } | undefined>;
	destroy(id: string): Promise<void>;
}

/*
 * The two storage areas specs/108 added, against a real datastore. "One connection per issuer per project" is
 * the primary key there, and only a real key holds under a concurrent write — which the in-memory store's map
 * cannot show. The usage record is written with no expiry, so a backend that read a missing ttl as "already
 * expired" would lose it to the sweeper. Shared by verify_mongodb.ts and verify_postgres.ts so both backends
 * answer the same questions in the same words.
 */
export async function verifyOutsideServers(
	store: OutsideAuthorizationServerStoreInstance,
	usage: UsageArea,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	const bucketId = `verify-outside-${stamp}`;
	const otherBucket = `verify-outside-other-${stamp}`;
	const issuer = `https://as-${stamp}.example`;
	const connection = (
		bucket: string,
		displayName: string
	): OutsideAuthorizationServer => ({
		_id: outsideServerId(bucket, issuer),
		bucketId: bucket,
		issuer,
		displayName,
		clients: [{ clientId: 'agent', externalClientId: 'agent-there' }],
		rules: [
			{
				appliesTo: { groupIds: ['g1'] },
				resources: [{ identifier: 'https://mcp.example', scopes: ['read'] }]
			}
		],
		signInClientId: 'portal',
		includeEmail: true,
		createdAt: new Date(),
		updatedAt: new Date()
	});

	const racing = await Promise.allSettled([
		store.create(connection(bucketId, 'race-a')),
		store.create(connection(bucketId, 'race-b'))
	]);
	check(
		'one issuer connected to one project twice at once: exactly one succeeds',
		racing.filter((r) => r.status === 'fulfilled').length === 1 &&
			racing.some((r) => r.status === 'rejected' && isTaken(r.reason)),
		racing.map((r) => r.status).join(', ')
	);

	const elsewhere = await store
		.create(connection(otherBucket, 'elsewhere'))
		.then(
			() => null,
			(error: unknown) => error
		);
	check(
		'the same issuer connected to another project is a connection of its own',
		elsewhere === null,
		String(elsewhere)
	);

	const id = outsideServerId(bucketId, issuer);
	const read = await store.find(id);
	check(
		'a connection reads back whole, nested rules and dates included',
		read !== null &&
			read.createdAt instanceof Date &&
			read.updatedAt instanceof Date &&
			read.clients[0]?.externalClientId === 'agent-there' &&
			typeof read.rules[0]?.appliesTo === 'object' &&
			read.signInClientId === 'portal',
		typeof read?.createdAt
	);

	if (read) {
		const { signInClientId: _dropped, ...rest } = read;
		await store.replace({
			...rest,
			displayName: 'renamed',
			rules: [
				{
					appliesTo: 'everyone',
					resources: [{ identifier: 'https://mcp.example', scopes: [] }]
				}
			]
		});
	}
	const replaced = await store.find(id);
	check(
		'a replace writes the whole record: a member left out is gone',
		replaced?.displayName === 'renamed' &&
			replaced.rules[0]?.appliesTo === 'everyone' &&
			!('signInClientId' in replaced),
		JSON.stringify(replaced)
	);

	const listed = await store.listByBucket(bucketId);
	check(
		'a project lists only its own connections',
		listed.length === 1 && listed[0]?._id === id,
		listed.map((c) => c.bucketId).join(', ')
	);

	await store.destroy(outsideServerId(otherBucket, issuer));
	check(
		'a deleted connection is gone',
		(await store.find(outsideServerId(otherBucket, issuer))) === null
	);
	const removed = await store.destroyByBucket(bucketId);
	check(
		'deleting the project’s connections counts each one removed',
		removed === 1 && (await store.listByBucket(bucketId)).length === 0,
		String(removed)
	);

	const key = `outside:verify-${stamp}`;
	await usage.upsert(key, { lastUsedAt: 1_700_000_000 });
	await usage.upsert(key, { lastUsedAt: 1_700_000_060 });
	const used = await usage.find(key);
	check(
		'a trust’s last use is stored with no expiry and the later write wins',
		used?.lastUsedAt === 1_700_000_060,
		JSON.stringify(used)
	);
	await usage.destroy(key);
	check(
		'a forgotten use reads as never used',
		(await usage.find(key)) === undefined
	);
}
