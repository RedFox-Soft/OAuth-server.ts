import type { UserStoreInstance } from '../lib/adapters/types.js';

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
}
