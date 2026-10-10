import { dayOf, endOf, monthOf } from '../activity/periods.js';
import type {
	ActivityBucketSnapshot,
	ActivityKind,
	ActivityMarkRecord,
	ActivityStoreInstance,
	ActivityTally
} from './types.js';

/*
 * What the three activity stores share: the record identities, the tally of a set of marks, and the second
 * half of `retire`. One copy, so the identity of a mark — which is the whole of what makes a person count
 * once — cannot differ between backends.
 */

export function markId(
	bucketId: string,
	period: string,
	accountId: string
): string {
	return `${bucketId}|${period}|${accountId}`;
}

export function figureId(bucketId: string, period: string): string {
	return `figure|${bucketId}|${period}`;
}

export function tombstoneId(bucketId: string): string {
	return `bucket|${bucketId}`;
}

export const SENTINEL_ID = 'countingSince';

export function emptyTally(): ActivityTally {
	return {
		total: 0,
		byKind: { local: 0, federated: 0, renewal: 0 },
		provisioned: 0
	};
}

export function tallyOf(
	marks: readonly Pick<ActivityMarkRecord, 'kinds' | 'provisioned'>[]
): ActivityTally {
	const tally = emptyTally();
	for (const mark of marks) {
		tally.total += 1;
		for (const kind of new Set<ActivityKind>(mark.kinds))
			tally.byKind[kind] += 1;
		if (mark.provisioned) tally.provisioned += 1;
	}
	return tally;
}

/* The month and the day an activity at `at` marks. */
export function periodsOf(at: Date): [string, string] {
	return [monthOf(at), dayOf(at)];
}

/*
 * Freeze a retired bucket's open month and day now. Exact rather than early: once the bucket is gone no
 * account of it can be resolved, so nothing can be active in it again. A failure is logged and swallowed —
 * the tombstone is already written, the marks are still there, and the closer freezes these periods later
 * under the tombstone's name.
 */
export async function freezeOpenPeriods(
	store: ActivityStoreInstance,
	bucket: ActivityBucketSnapshot,
	at: Date
): Promise<void> {
	for (const period of periodsOf(at)) {
		try {
			if (at.getTime() < endOf(period).getTime()) {
				await store.freeze(bucket._id, period, bucket, at);
			}
		} catch (error) {
			console.error('activity: could not freeze a retired bucket period', {
				bucketId: bucket._id,
				period,
				error
			});
		}
	}
}
