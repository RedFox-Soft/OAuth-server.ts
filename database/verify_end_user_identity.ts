import type {
	UserBucketStoreInstance,
	UserStoreInstance
} from '../lib/adapters/types.js';

/*
 * By name rather than by class: a value import of the adapter types would load what the callers deliberately
 * import only after their throwaway-database guard.
 */
function isDuplicate(error: unknown, field: string): boolean {
	return (
		error instanceof Error &&
		error.name === 'DuplicateEndUserError' &&
		'field' in error &&
		error.field === field
	);
}

/*
 * The provisioned-identity uniqueness rules, against a real datastore: what the in-memory store can only
 * simulate with a scan is, here, the unique sparse indexes the per-bucket area declares — and they are what
 * holds under concurrency. Shared by verify_mongodb.ts and verify_postgres.ts so both backends answer the same
 * questions in the same words.
 *
 * `store` must be a user store whose area was provisioned after the indexes were declared (a bucket created
 * by the script itself), so the check is of the declaration, not of whatever an old area happens to hold.
 */
export async function verifyEndUserIdentity(
	store: UserStoreInstance,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	const create = (label: string) =>
		store.create(`${label}-${stamp}@example.com`, 'hash');

	const first = await create('identity-a');
	const second = await create('identity-b');
	await store.update(first._id, { userName: `Grace.Hopper.${stamp}` });
	const caseVariant = await store
		.update(second._id, { userName: `grace.hopper.${stamp}` })
		.then(
			() => undefined,
			(error: unknown) => error
		);
	check(
		'two usernames differing only in letter case collide',
		isDuplicate(caseVariant, 'userName'),
		String(caseVariant)
	);

	const third = await create('identity-c');
	const fourth = await create('identity-d');
	const withoutId = await Promise.allSettled([
		store.update(third._id, { provisionedBy: `conn-${stamp}` }),
		store.update(fourth._id, { provisionedBy: `conn-${stamp}` })
	]);
	check(
		'two users of one connection without an external identifier do not collide, which is what sparse buys',
		withoutId.every((r) => r.status === 'fulfilled'),
		withoutId.map((r) => r.status).join(', ')
	);

	const racing = await Promise.allSettled([
		store.update(third._id, { externalId: 'same' }),
		store.update(fourth._id, { externalId: 'same' })
	]);
	check(
		'one external identifier given to two users of one connection at once: exactly one succeeds',
		racing.filter((r) => r.status === 'fulfilled').length === 1,
		racing.map((r) => r.status).join(', ')
	);

	const other = await create('identity-e');
	const elsewhere = await store
		.update(other._id, { provisionedBy: `other-${stamp}`, externalId: 'same' })
		.then(
			() => 'accepted',
			(error: unknown) => String(error)
		);
	check(
		'the same external identifier from another connection is accepted',
		elsewhere === 'accepted',
		elsewhere
	);

	const { users, totalResults } = await store.query(
		{ userName: `GRACE.HOPPER.${stamp}` },
		{ startIndex: 1, count: 10 }
	);
	check(
		'a lookup by username finds the user in another letter case',
		totalResults === 1 && users[0]?._id === first._id,
		`${totalResults}`
	);

	/*
	 * Who is linked to a provider: what a provider's issuer change and deletion consult. The element match
	 * on the embedded `federated` array is what the in-memory store can only imitate with a scan.
	 */
	const providerId = `verify-provider-${stamp}`;
	const linkedA = await create('linked-a');
	const linkedB = await create('linked-b');
	const elsewhereLinked = await create('linked-elsewhere');
	for (const user of [linkedA, linkedB]) {
		await store.update(user._id, {
			federated: [{ providerId, sub: user._id, linkedAt: new Date() }]
		});
	}
	await store.update(elsewhereLinked._id, {
		federated: [
			{ providerId: `${providerId}-other`, sub: 'x', linkedAt: new Date() }
		]
	});
	const linked = await store.findLinkedTo(providerId);
	check(
		'the accounts linked to a provider are found, and only those',
		linked.length === 2 &&
			linked.every((u) => u._id === linkedA._id || u._id === linkedB._id),
		linked.map((u) => u._id).join(',')
	);
	const one = await store.findLinkedTo(providerId, 1);
	check(
		'a limit bounds the accounts found linked to a provider',
		one.length === 1,
		`${one.length}`
	);

	/*
	 * A bucket's tally, counted by the datastore: the predicates reach inside each document, so a field
	 * stored in the wrong shape would count nothing here and everything in memory. A link list emptied and
	 * one removed must both count as unlinked, and an authenticator cleared as none.
	 */
	const before = await store.tally();
	const complete = await store.create(
		`tally-complete-${stamp}@example.com`,
		'hash',
		true
	);
	await store.update(complete._id, {
		totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 },
		federated: [{ providerId, sub: `tally-${stamp}`, linkedAt: new Date() }]
	});
	const emptied = await create('tally-emptied');
	await store.update(emptied._id, {
		federated: [{ providerId, sub: `emptied-${stamp}`, linkedAt: new Date() }]
	});
	await store.update(emptied._id, { federated: [] });
	const cleared = await store.create(
		`tally-cleared-${stamp}@example.com`,
		'hash',
		true
	);
	await store.update(cleared._id, {
		totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 },
		federated: [{ providerId, sub: `cleared-${stamp}`, linkedAt: new Date() }]
	});
	await store.update(cleared._id, { totp: undefined, federated: undefined });
	const after = await store.tally();
	const delta = {
		total: after.total - before.total,
		unverified: after.unverified - before.unverified,
		withoutAuthenticator:
			after.withoutAuthenticator - before.withoutAuthenticator,
		withoutLinkedIdentity:
			after.withoutLinkedIdentity - before.withoutLinkedIdentity
	};
	check(
		"a bucket's tally counts unverified, unenrolled and unlinked accounts, an emptied or removed link list alike",
		delta.total === 3 &&
			delta.unverified === 1 &&
			delta.withoutAuthenticator === 2 &&
			delta.withoutLinkedIdentity === 2,
		JSON.stringify(delta)
	);
	const listed = await store.list();
	check(
		'the tally total is the number of accounts the bucket holds',
		after.total === listed.length,
		`${after.total} vs ${listed.length}`
	);
}

/*
 * An address change forgets the arrivals recorded at the old address, in the same write: kept, they would
 * report a new hostname as reached before any request had arrived at it. Shared here because both fidelity
 * scripts already run the end-user checks against a bucket they created.
 */
export async function verifyAddressChangeForgetsArrivals(
	buckets: UserBucketStoreInstance,
	bucketId: string,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	await buckets.setAddress(bucketId, { host: `old-${stamp}.example.test` });
	await buckets.update(bucketId, {
		hostFirstSeenAt: new Date(),
		hostLastSeenAt: new Date()
	});
	const moved = await buckets.setAddress(bucketId, {
		host: `new-${stamp}.example.test`
	});
	check(
		'a new hostname carries no arrivals from the old one',
		moved?.host === `new-${stamp}.example.test` &&
			moved.hostFirstSeenAt === undefined &&
			moved.hostLastSeenAt === undefined,
		JSON.stringify(moved)
	);
	const reread = await buckets.find(bucketId);
	check(
		'the forgotten arrivals stay forgotten on a fresh read',
		reread?.hostFirstSeenAt === undefined &&
			reread?.hostLastSeenAt === undefined &&
			reread?.slug === undefined,
		JSON.stringify(reread)
	);
}
