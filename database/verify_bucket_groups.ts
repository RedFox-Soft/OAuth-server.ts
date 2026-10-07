import type { BucketGroupStoreInstance } from '../lib/adapters/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/* By name rather than by class, for the reason verify_provisioning_connections.ts gives. */
function isTaken(error: unknown, field: string): boolean {
	return (
		error instanceof Error &&
		error.name === 'UniqueValueTaken' &&
		'field' in error &&
		error.field === field
	);
}

function median(values: number[]): number {
	const sorted = [...values].sort((a, b) => a - b);
	return sorted[Math.floor(sorted.length / 2)];
}

/*
 * Bucket groups against a real datastore (specs/071): the case-insensitive name index under a concurrent
 * create, a refused rename writing no membership, membership writes that are idempotent — and SC-004, how long a
 * 50-member change takes while a group grows to 10,000, which only a real database can say. Shared by
 * verify_mongodb.ts and verify_postgres.ts so both backends answer the same questions in the same words.
 */
export async function verifyBucketGroups(
	store: BucketGroupStoreInstance,
	check: Check
): Promise<string[]> {
	const stamp = Date.now();
	const bucketId = `verify-groups-${stamp}`;

	const raced = await Promise.allSettled(
		['Finance', 'finance'].map((displayName, i) =>
			store.create({ _id: `race-${i}-${stamp}`, bucketId, displayName })
		)
	);
	check(
		'two groups whose names differ only in case cannot both be created, even at once',
		raced.filter((r) => r.status === 'fulfilled').length === 1 &&
			raced.some(
				(r) => r.status === 'rejected' && isTaken(r.reason, 'displayName')
			)
	);

	const legal = await store.create(
		{ _id: `legal-${stamp}`, bucketId, displayName: 'Legal' },
		['u1']
	);
	let refused: unknown;
	try {
		await store.change(legal._id, {
			attributes: { displayName: 'FINANCE' },
			add: ['u2']
		});
	} catch (error) {
		refused = error;
	}
	check(
		'a change refused for a taken name writes no membership',
		isTaken(refused, 'displayName') &&
			JSON.stringify(await store.memberIds(legal._id)) ===
				JSON.stringify(['u1'])
	);

	await store.change(legal._id, { add: ['u1', 'u3'] });
	await store.change(legal._id, { add: ['u3'] });
	check(
		'adding a member twice leaves one membership',
		(await store.memberCount(legal._id)) === 2
	);

	/*
	 * SC-004: a group filled to 10,000 members by changes of 50, the way Entra fills one. Every change must stay
	 * under a second, and the last ones must cost about what the first ones did — a change costs what the change
	 * is, never what the group is.
	 */
	const big = await store.create({
		_id: `big-${stamp}`,
		bucketId,
		displayName: 'Everyone'
	});
	const timings: number[] = [];
	for (let batch = 0; batch < 200; batch++) {
		const add = Array.from(
			{ length: 50 },
			(_, i) => `m${(batch * 50 + i).toString().padStart(6, '0')}`
		);
		const started = performance.now();
		await store.change(big._id, { add });
		timings.push(performance.now() - started);
	}
	const first = median(timings.slice(0, 20));
	const last = median(timings.slice(-20));
	const slowest = Math.max(...timings);
	check(
		'every 50-member change into a group growing to 10,000 completes in under a second',
		slowest < 1000,
		`slowest ${slowest.toFixed(1)} ms`
	);
	check(
		'the cost of a change does not grow with the group',
		last < Math.max(first * 3, first + 20),
		`median of the first 20: ${first.toFixed(1)} ms, of the last 20: ${last.toFixed(1)} ms`
	);
	const readStarted = performance.now();
	const everyone = await store.memberIds(big._id);
	const readMs = performance.now() - readStarted;
	check('a 10,000-member group reads back whole', everyone.length === 10_000);

	await store.destroyByBucket(bucketId);
	check(
		'deleting a bucket’s groups leaves none of their memberships',
		(await store.memberCount(big._id)) === 0 &&
			(await store.find(big._id)) === null
	);

	return [
		`50-member change: first ${first.toFixed(1)} ms, last ${last.toFixed(1)} ms, slowest ${slowest.toFixed(1)} ms`,
		`10,000-member read: ${readMs.toFixed(1)} ms`
	];
}
