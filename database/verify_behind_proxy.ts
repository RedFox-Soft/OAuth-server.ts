import type {
	BehindProxyApp,
	BehindProxyAppStoreInstance
} from '../lib/adapters/types.js';

/* By name rather than by class, for the reason verify_provisioning_connections.ts gives. */
function isTaken(error: unknown): boolean {
	return error instanceof Error && error.name === 'UniqueValueTaken';
}

/* What the BehindProxySession model area is reached through: the generic model adapter, on either backend. */
interface SessionArea {
	upsert(
		id: string,
		payload: Record<string, unknown>,
		expiresIn?: number
	): Promise<void>;
	findByIndexed(field: string, value: string): Promise<unknown[]>;
	destroy(id: string): Promise<void>;
}

/*
 * The storage specs/122 added, against a real datastore. "One app per address per project" is a unique index
 * there, refused under a concurrent write and on an update that moves an address, which the in-memory store's
 * synchronous check cannot show; the checklist's first times must survive a second report in one statement; and
 * an app's sessions must be listable by the app through the index the inventory declares. Shared by
 * verify_mongodb.ts and verify_postgres.ts so both backends answer the same questions in the same words.
 */
export async function verifyBehindProxy(
	store: BehindProxyAppStoreInstance,
	sessions: SessionArea,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	const bucketId = `verify-proxy-${stamp}`;
	const otherBucket = `verify-proxy-other-${stamp}`;
	const address = `https://app-${stamp}.example`;
	const app = (id: string, bucket: string, at: string): BehindProxyApp => ({
		_id: id,
		bucketId: bucket,
		name: id,
		address: at,
		proxyKind: 'caddy',
		rules: [
			{ path: '/', who: { kind: 'groups', groupIds: ['g1'] } },
			{ path: '/Docs', who: { kind: 'public', subtree: true } }
		],
		createdAt: new Date(),
		updatedAt: new Date()
	});

	const racing = await Promise.allSettled([
		store.create(app(`a-${stamp}`, bucketId, address)),
		store.create(app(`b-${stamp}`, bucketId, address))
	]);
	check(
		'one address given to two apps of one project at once: exactly one succeeds',
		racing.filter((r) => r.status === 'fulfilled').length === 1 &&
			racing.some((r) => r.status === 'rejected' && isTaken(r.reason)),
		racing.map((r) => r.status).join(', ')
	);
	const winner = racing[0].status === 'fulfilled' ? `a-${stamp}` : `b-${stamp}`;

	const elsewhere = await store
		.create(app(`c-${stamp}`, otherBucket, address))
		.then(
			() => null,
			(error: unknown) => error
		);
	check(
		'the same address in another project is an app of its own',
		elsewhere === null,
		String(elsewhere)
	);

	const read = await store.find(winner);
	check(
		'an app reads back whole, nested rules and dates included',
		read !== null &&
			read.createdAt instanceof Date &&
			read.rules[0]?.who.kind === 'groups' &&
			read.rules[1]?.who.kind === 'public' &&
			read.rules[1].who.subtree &&
			read.firstAskedAt === undefined,
		JSON.stringify(read)
	);

	const second = `d-${stamp}`;
	await store.create(app(second, bucketId, `https://other-${stamp}.example`));
	const moved = await store.update(second, { address }).then(
		() => null,
		(error: unknown) => error
	);
	check(
		'moving an app onto an address its project already uses is refused as taken',
		isTaken(moved),
		String(moved)
	);
	const renamed = await store.update(second, {
		name: 'renamed',
		rules: [{ path: '/', who: { kind: 'project' } }]
	});
	check(
		'an update changes what it names, replaces the rules whole and keeps the rest',
		renamed?.name === 'renamed' &&
			renamed.rules.length === 1 &&
			renamed.rules[0]?.who.kind === 'project' &&
			renamed.address === `https://other-${stamp}.example`,
		JSON.stringify(renamed)
	);
	check(
		'an update of an app that is not there answers nothing',
		(await store.update(`missing-${stamp}`, { name: 'x' })) === null
	);

	const first = new Date('2026-01-01T00:00:00Z');
	const later = new Date('2026-01-02T00:00:00Z');
	await store.noteUsage(winner, { firstAskedAt: first, lastAskedAt: first });
	await store.noteUsage(winner, {
		firstAskedAt: later,
		firstSignInAt: later,
		lastAskedAt: later
	});
	const used = await store.find(winner);
	check(
		'a first time once recorded stays the first; the last time moves',
		used?.firstAskedAt?.getTime() === first.getTime() &&
			used.firstSignInAt?.getTime() === later.getTime() &&
			used.lastAskedAt?.getTime() === later.getTime() &&
			used.firstAllowedAt === undefined &&
			used.name === winner,
		JSON.stringify(used)
	);

	const listed = await store.listByBucket(bucketId);
	check(
		'a project lists only its own apps',
		listed.length === 2 && listed.every((a) => a.bucketId === bucketId),
		listed.map((a) => a.bucketId).join(', ')
	);

	const sessionId = `verify-proxy-session-${stamp}`;
	await sessions.upsert(
		sessionId,
		{
			accountId: `account-${stamp}`,
			appId: winner,
			bucketId,
			createdAt: Math.floor(stamp / 1000),
			exp: Math.floor(stamp / 1000) + 3600
		},
		3600
	);
	const ofApp = await sessions.findByIndexed('appId', winner);
	check(
		'an app’s sessions are found by the app',
		ofApp.length === 1,
		JSON.stringify(ofApp)
	);
	await sessions.destroy(sessionId);

	/*
	 * A path that asks for a sign-in with a code (specs/128): the flag is stored on the closed condition only when on,
	 * and read back as written, so the decision and the summary see it on either backend.
	 */
	await store.update(winner, {
		rules: [
			{ path: '/', who: { kind: 'groups', groupIds: ['g1'] } },
			{
				path: '/admin',
				who: {
					kind: 'conditional',
					who: { kind: 'groups', groupIds: ['g1'] },
					conditions: [{ kind: 'fresh', maxAgeMinutes: 15, withCode: true }]
				}
			}
		]
	});
	const withCode = await store.find(winner);
	check(
		'a fresh condition that asks for a code is stored and read back with the flag',
		JSON.stringify(withCode?.rules).includes('"withCode":true'),
		JSON.stringify(withCode?.rules)
	);

	await store.delete(`c-${stamp}`);
	check('a deleted app is gone', (await store.find(`c-${stamp}`)) === null);
	const removed = await store.destroyByBucket(bucketId);
	check(
		'deleting the project’s apps answers each one removed',
		removed.length === 2 &&
			removed.includes(winner) &&
			removed.includes(second) &&
			(await store.listByBucket(bucketId)).length === 0,
		removed.join(', ')
	);
}
