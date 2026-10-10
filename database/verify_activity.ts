import type { ActivityStoreInstance } from '../lib/adapters/types.js';
import { monthOf } from '../lib/activity/periods.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/*
 * Monthly and daily active users (specs/076) against a real datastore. What an in-memory double cannot show
 * is whether concurrent first marks of one person stay one record holding every kind, whether a figure is
 * insert-if-absent on the server, and whether an expired mark is reclaimed. Shared by verify_mongodb.ts and
 * verify_postgres.ts so both backends answer the same questions in the same words.
 *
 * `reclaimed` is the backend's own question, because the two reclaim differently: PostgreSQL's sweeper can
 * be run on demand, MongoDB's TTL monitor cannot, so there it asks whether the TTL index is in place.
 */
export async function verifyActivity(
	store: ActivityStoreInstance,
	reclaimed: (markId: string) => Promise<boolean>,
	check: Check
): Promise<void> {
	const stamp = Date.now();
	const bucketId = `activity-${String(stamp)}`;
	const at = new Date();
	const month = monthOf(at);
	const kinds = ['local', 'federated', 'renewal'] as const;

	await Promise.all(
		Array.from({ length: 20 }, (_, i) =>
			store.mark({
				bucketId,
				accountId: 'concurrent',
				kind: kinds[i % kinds.length],
				provisioned: false,
				at
			})
		)
	);
	const counted = await store.count(bucketId, month, at);
	check(
		'twenty concurrent marks of one person leave one record holding every kind sent',
		counted.total === 1 &&
			counted.byKind.local === 1 &&
			counted.byKind.federated === 1 &&
			counted.byKind.renewal === 1,
		JSON.stringify(counted)
	);

	/* The closer's and the overview's work list; on MongoDB the Stable API refuses `distinct`. */
	check(
		'the buckets with marks in a period are listed',
		(await store.bucketsWithMarks(month, at)).includes(bucketId)
	);
	check(
		'every bucket with marks in a period is counted',
		(await store.countPeriod(month, at)).get(bucketId)?.total === 1
	);

	const first = await store.freeze(bucketId, month, { name: 'verify' }, at);
	await store.mark({
		bucketId,
		accountId: 'late',
		kind: 'local',
		provisioned: false,
		at
	});
	const again = await store.freeze(bucketId, month, { name: 'verify' }, at);
	check(
		'a second freeze returns the first figure after a new mark',
		again.total === first.total &&
			again.frozenAt.getTime() === first.frozenAt.getTime(),
		JSON.stringify({ first: first.total, again: again.total })
	);

	const longAgo = new Date(
		Date.UTC(at.getUTCFullYear() - 2, at.getUTCMonth(), 1)
	);
	await store.mark({
		bucketId,
		accountId: 'expired',
		kind: 'local',
		provisioned: false,
		at: longAgo
	});
	const expiredMonth = monthOf(longAgo);
	check(
		'a mark past its expiry is not counted',
		(await store.count(bucketId, expiredMonth, at)).total === 0
	);
	check(
		'a mark past its expiry is reclaimed',
		await reclaimed(`${bucketId}|${expiredMonth}|expired`)
	);

	/*
	 * The owner a deleted bucket's tombstone keeps (specs/077) is written insert-if-absent with the rest of
	 * it: a second deletion request, even one naming another owner, must not rewrite whose bucket it was.
	 */
	const retired = `${bucketId}-retired`;
	const snapshot = { _id: retired, name: 'verify', createdAt: at };
	await store.retire(snapshot, { groupId: 'owner-1', label: 'First' }, at);
	await store.retire(snapshot, { groupId: 'owner-2', label: 'Second' }, at);
	const tombstone = await store.tombstone(retired);
	check(
		'a tombstone keeps the owner it was first written with',
		tombstone?.ownerGroupId === 'owner-1' && tombstone.ownerLabel === 'First',
		JSON.stringify(tombstone)
	);
}
