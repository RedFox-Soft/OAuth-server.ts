import type {
	EndUserFilter,
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
	/*
	 * The two counts a sign-in change is previewed with (specs/083), against the datastore: a link counts only
	 * when its provider is among the enabled ones — matched inside the embedded array — and a password is
	 * assumed unless the account says it has none.
	 */
	const enabled = { enabledProviderIds: [providerId] };
	const beforeSignIn = await store.tally(enabled);
	const atProvider = await create('tally-at-provider');
	await store.update(atProvider._id, {
		totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 },
		federated: [{ providerId, sub: `at-${stamp}`, linkedAt: new Date() }]
	});
	const atOther = await create('tally-at-other');
	await store.update(atOther._id, {
		federated: [
			{
				providerId: `${providerId}-off`,
				sub: `off-${stamp}`,
				linkedAt: new Date()
			}
		]
	});
	const passwordless = await create('tally-passwordless');
	await store.update(passwordless._id, { passwordSet: false });
	const afterSignIn = await store.tally(enabled);
	const signInDelta = {
		withoutEnabledLink:
			afterSignIn.withoutEnabledLink - beforeSignIn.withoutEnabledLink,
		passwordWithoutAuthenticator:
			afterSignIn.passwordWithoutAuthenticator -
			beforeSignIn.passwordWithoutAuthenticator
	};
	check(
		'a link counts only to an enabled provider, and an account without a password is never asked for an authenticator',
		signInDelta.withoutEnabledLink === 2 &&
			signInDelta.passwordWithoutAuthenticator === 1,
		JSON.stringify(signInDelta)
	);
	const noneEnabled = await store.tally({ enabledProviderIds: [] });
	check(
		'with no enabled provider nobody has an enabled link',
		noneEnabled.withoutEnabledLink === noneEnabled.total,
		`${noneEnabled.withoutEnabledLink} of ${noneEnabled.total}`
	);

	const listed = await store.list();
	check(
		'the tally total is the number of accounts the bucket holds',
		afterSignIn.total === listed.length,
		`${afterSignIn.total} vs ${listed.length}`
	);
}

/*
 * The console's users search and filters, against a real datastore (specs/082): a prefix on the stored
 * lower-case email or username key — an anchored regular expression on MongoDB, LIKE over a
 * text_pattern_ops index on PostgreSQL — where the in-memory store only compares strings. The characters
 * each language gives a meaning (`%` and `_` to LIKE, `.` to a regular expression) must be taken literally,
 * and a page must come back in the same email order with the same total on both backends.
 *
 * Every account here shares one stamped prefix, and every query carries it, so the answers are about these
 * accounts alone whatever else the area holds.
 */
export async function verifyEndUserSearch(
	store: UserStoreInstance,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const prefix = `s${Date.now()}-`;
	const page = { startIndex: 1, count: 50 };
	const made: Record<string, string> = {};
	for (const local of [
		'alice',
		'100%off',
		'100xoff',
		'a_b',
		'axb',
		'c.d',
		'cxd',
		'deactivated',
		'locked',
		'unverified',
		'enrolled',
		'directory'
	]) {
		const user = await store.create(
			`${prefix}${local}@example.com`,
			'hash',
			local !== 'unverified'
		);
		made[local] = user._id;
	}
	await store.update(made.deactivated, { active: false });
	await store.update(made.locked, {
		lockedLocally: { at: new Date(), by: 'verify', reason: 'verify' }
	});
	await store.update(made.enrolled, {
		totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 }
	});
	await store.update(made.directory, {
		provisionedBy: `conn-${prefix}`,
		userName: `${prefix}Grace.Hopper`
	});

	const found = async (filter: EndUserFilter) =>
		(await store.query(filter, page)).users
			.map((u) => u.email.slice(prefix.length).split('@')[0])
			.sort();
	const expectFound = async (
		name: string,
		filter: EndUserFilter,
		wanted: string[]
	) => {
		const got = await found(filter);
		check(name, JSON.stringify(got) === JSON.stringify(wanted), got.join(','));
	};

	await expectFound(
		'a search finds the start of an email in another letter case',
		{ search: `${prefix.toUpperCase()}ALI` },
		['alice']
	);
	await expectFound(
		'a percent sign in a search is a literal, not a wildcard',
		{ search: `${prefix}100%` },
		['100%off']
	);
	await expectFound(
		'an underscore in a search is a literal, not a wildcard',
		{ search: `${prefix}a_` },
		['a_b']
	);
	await expectFound(
		'a dot in a search is a literal, not a wildcard',
		{ search: `${prefix}c.` },
		['c.d']
	);
	await expectFound(
		'a search finds the start of a username in another letter case',
		{ search: `${prefix}grace.h`.toUpperCase() },
		['directory']
	);
	await expectFound(
		'a search finds an account by its exact id',
		{ search: made.alice },
		['alice']
	);
	await expectFound(
		'the deactivated filter finds deactivated accounts',
		{ search: prefix, active: false },
		['deactivated']
	);
	await expectFound(
		'the locked filter finds locked accounts',
		{ search: prefix, locked: true },
		['locked']
	);
	await expectFound(
		'the unverified filter finds unverified accounts',
		{ search: prefix, verified: false },
		['unverified']
	);
	await expectFound(
		'the authenticator filter finds enrolled accounts',
		{ search: prefix, totpEnrolled: true },
		['enrolled']
	);
	await expectFound(
		'the directory filter finds a connection’s accounts',
		{ search: prefix, local: false },
		['directory']
	);
	const local = await found({ search: prefix, local: true });
	check(
		'the local filter leaves a connection’s accounts out',
		local.length === 11 && !local.includes('directory'),
		local.join(',')
	);

	const first = await store.query(
		{ search: prefix },
		{ startIndex: 1, count: 3 },
		'email'
	);
	const second = await store.query(
		{ search: prefix },
		{ startIndex: 4, count: 3 },
		'email'
	);
	const all = await store.query({ search: prefix }, page, 'email');
	const emails = all.users.map((u) => u.email);
	const byteOrder = [...emails].sort((a, b) =>
		Buffer.compare(Buffer.from(a), Buffer.from(b))
	);
	check(
		'a page in email order is in byte order, with the total of every match',
		JSON.stringify(emails) === JSON.stringify(byteOrder) &&
			all.totalResults === 12 &&
			first.totalResults === 12,
		`${all.totalResults}: ${emails.join(',')}`
	);
	check(
		'consecutive pages continue the same email order',
		JSON.stringify([...first.users, ...second.users].map((u) => u.email)) ===
			JSON.stringify(emails.slice(0, 6)),
		[...first.users, ...second.users].map((u) => u.email).join(',')
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
