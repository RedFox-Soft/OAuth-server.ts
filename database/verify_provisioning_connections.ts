import type {
	NewProvisioningConnection,
	ProvisioningConnectionStoreInstance
} from '../lib/adapters/types.js';

/*
 * By name rather than by class: a value import of the adapter types would load what the callers deliberately
 * import only after their throwaway-database guard.
 */
function isTaken(error: unknown, field: string): boolean {
	return (
		error instanceof Error &&
		error.name === 'UniqueValueTaken' &&
		'field' in error &&
		error.field === field
	);
}

/*
 * The provisioning-connection uniqueness rules against a real datastore: "one connection per provider" and
 * "one connection per static token" are unique indexes there, and only a real index holds under a concurrent
 * write — which the in-memory store's scan cannot show. Shared by verify_mongodb.ts and verify_postgres.ts so
 * both backends answer the same questions in the same words.
 */
export async function verifyProvisioningConnections(
	store: ProvisioningConnectionStoreInstance,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	const bucketId = `verify-bucket-${stamp}`;
	const base = (id: string, providerId: string): NewProvisioningConnection => ({
		_id: `${id}-${stamp}`,
		bucketId,
		displayName: id,
		enabled: true,
		providerId,
		correlation: { claim: 'oid', attribute: 'externalId' },
		emailTrust: 'untrusted',
		oauthCredential: null
	});

	const racing = await Promise.allSettled([
		store.create(base('race-a', 'corp')),
		store.create(base('race-b', 'corp'))
	]);
	check(
		'two connections bound to one provider at once: exactly one succeeds',
		racing.filter((r) => r.status === 'fulfilled').length === 1 &&
			racing.some(
				(r) => r.status === 'rejected' && isTaken(r.reason, 'provider')
			),
		racing.map((r) => r.status).join(', ')
	);

	const withoutTokens = await Promise.allSettled([
		store.create(base('quiet-a', 'one')),
		store.create(base('quiet-b', 'two'))
	]);
	check(
		'two connections without a static token coexist, which is what sparse buys',
		withoutTokens.every((r) => r.status === 'fulfilled'),
		withoutTokens.map((r) => r.status).join(', ')
	);

	await store.update(`quiet-a-${stamp}`, {
		staticTokenDigest: `digest-${stamp}`
	});
	const reused = await store
		.update(`quiet-b-${stamp}`, { staticTokenDigest: `digest-${stamp}` })
		.then(
			() => undefined,
			(error: unknown) => error
		);
	check(
		'one static-token digest given to two connections collides',
		isTaken(reused, 'staticToken'),
		String(reused)
	);

	await store.update(`quiet-a-${stamp}`, { staticTokenDigest: undefined });
	const found = await store.findByStaticTokenDigest(`digest-${stamp}`);
	check(
		'a revoked static token is gone from the digest index',
		found === null,
		String(found?._id)
	);

	const read = await store.find(`quiet-b-${stamp}`);
	check(
		'dates round-trip as dates',
		read?.createdAt instanceof Date && read.updatedAt instanceof Date,
		typeof read?.createdAt
	);

	const removed = await store.destroyByBucket(bucketId);
	check(
		'deleting the bucket’s connections names each one removed',
		removed.length === 3,
		removed.join(', ')
	);
}
