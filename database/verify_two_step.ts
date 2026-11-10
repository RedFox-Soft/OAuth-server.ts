import type {
	ModelAdapter,
	UserBucketStoreInstance,
	UserStoreInstance
} from '../lib/adapters/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/*
 * A person's own two-step verification (specs/126) against a real datastore. What the in-memory double cannot show:
 * that the new optional fields on the person and the project are written and removed as the backends store documents
 * (a field set to undefined must go, not linger), that a mailed link is spent once under concurrency, and that the
 * spent-step and day-window records behave as insert-if-absent and atomic increments do. Shared by verify_mongodb.ts and
 * verify_postgres.ts.
 */
export async function verifyTwoStep(
	stores: {
		buckets: UserBucketStoreInstance;
		users: (bucketId: string) => UserStoreInstance;
		links: ModelAdapter<Record<string, unknown>>;
		spent: ModelAdapter<Record<string, unknown>>;
		attempts: ModelAdapter<Record<string, unknown>>;
		/* An application's requirement of a code (specs/127): a base key on the stored client document. */
		clients: ModelAdapter<Record<string, unknown>>;
	},
	check: Check
): Promise<void> {
	const stamp = String(Date.now());

	{
		const clientId = `verify-require-code-${stamp}`;
		const bucketId = `verify-require-code-bucket-${stamp}`;
		await stores.clients.upsert(clientId, {
			clientId,
			bucketId,
			'signIn.requireCode': true
		});
		const stored = await stores.clients.find(clientId);
		const listed = await stores.clients.findByIndexed('bucketId', bucketId);
		check(
			"an application's requirement of a code is stored with the client and read back by its project",
			stored?.['signIn.requireCode'] === true &&
				listed.some((record) => record['signIn.requireCode'] === true),
			JSON.stringify({ stored, listed: listed.length })
		);
		await stores.clients.destroy(clientId);
	}
	const exp = Math.floor(Date.now() / 1000) + 600;

	const bucket = await stores.buckets.create({
		name: `verify two-step ${stamp}`,
		ownerGroupId: 'verify-two-step'
	});
	await stores.buckets.update(bucket._id, { totpSelfService: false });
	const off = await stores.buckets.find(bucket._id);
	await stores.buckets.update(bucket._id, { totpSelfService: undefined });
	const cleared = await stores.buckets.find(bucket._id);
	check(
		"a project's self-service setting is stored, and removed when cleared",
		off?.totpSelfService === false && cleared?.totpSelfService === undefined,
		JSON.stringify({
			off: off?.totpSelfService,
			cleared: cleared?.totpSelfService
		})
	);

	const users = stores.users(bucket._id);
	const person = await users.create(`two-step-${stamp}@x.io`, 'h', true);
	await users.update(person._id, {
		totp: {
			secret: 'JBSWY3DPEHPK3PXP',
			enrolledAt: new Date(),
			lastStep: 7,
			via: 'self'
		},
		totpProofRequired: true
	});
	const marked = await users.find(person._id);
	await users.update(person._id, { totpProofRequired: undefined });
	const unmarked = await users.find(person._id);
	check(
		"a person's factor keeps how it was set up, and the removal mark is stored and removed",
		marked?.totp?.via === 'self' &&
			marked.totpProofRequired === true &&
			unmarked?.totpProofRequired === undefined &&
			unmarked?.totp?.via === 'self',
		JSON.stringify({
			marked: marked?.totp?.via,
			proof: unmarked?.totpProofRequired
		})
	);

	const linkId = `verify-link-${stamp}`;
	await stores.links.upsert(
		linkId,
		{
			accountId: person._id,
			bucketId: bucket._id,
			purpose: 'enrol',
			holder: 'account:verify',
			exp
		},
		600
	);
	const spends = await Promise.all(
		Array.from({ length: 5 }, () => stores.links.consume(linkId))
	);
	check(
		'a mailed link is spent exactly once by racing followers',
		spends.filter(Boolean).length === 1,
		JSON.stringify(spends)
	);

	const stepId = `verify-step-${stamp}`;
	const steps = await Promise.all(
		Array.from({ length: 5 }, () =>
			stores.spent.create(stepId, { accountId: person._id, exp }, 120)
		)
	);
	check(
		'a code step is spent exactly once by racing verifications',
		steps.filter(Boolean).length === 1,
		JSON.stringify(steps)
	);

	const dayId = `verify-attempts-${stamp}:day`;
	await stores.attempts.create(
		dayId,
		{
			accountId: person._id,
			failures: 0,
			windowStart: Math.floor(Date.now() / 1000),
			exp
		},
		600
	);
	const counted = await Promise.all(
		Array.from({ length: 8 }, () =>
			stores.attempts.increment(dayId, 'failures')
		)
	);
	check(
		'the day window counts every racing wrong code',
		JSON.stringify([...counted].sort((a, b) => Number(a) - Number(b))) ===
			JSON.stringify([1, 2, 3, 4, 5, 6, 7, 8]),
		JSON.stringify(counted)
	);

	await users.destroy(person._id);
	await stores.buckets.destroy(bucket._id);
}
