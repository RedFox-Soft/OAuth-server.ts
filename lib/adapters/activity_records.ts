import { dayOf, endOf, monthOf } from '../activity/periods.js';
import type {
	ActivityBucketSnapshot,
	ActivityKind,
	ActivityMarkRecord,
	LastActiveFilter,
	LastMarked,
	ActivityOwner,
	ActivityStoreInstance,
	ActivityTally,
	ActivityTombstone
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

/*
 * The record a deleted bucket leaves. One shape for the three stores, each of which writes it
 * insert-if-absent, so a repeated deletion request — or one naming a different owner — changes nothing.
 */
export function tombstoneOf(
	bucket: ActivityBucketSnapshot,
	owner: ActivityOwner,
	at: Date
): ActivityTombstone {
	return {
		_id: tombstoneId(bucket._id),
		type: 'tombstone',
		bucketId: bucket._id,
		bucketName: bucket.name,
		...(bucket.slug === undefined ? {} : { bucketSlug: bucket.slug }),
		ownerGroupId: owner.groupId,
		ownerLabel: owner.label,
		createdAt: bucket.createdAt,
		deletedAt: at
	};
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

/*
 * The latest of one person's live marks (specs/134 research R5): the latest day if any, else the latest month. A day
 * mark implies its month's, so the latest day is never older than the latest month.
 */
export function latestMarked(periods: Iterable<string>): LastMarked | null {
	let day: string | null = null;
	let month: string | null = null;
	for (const period of periods) {
		if (period.length === 7) {
			if (month === null || period > month) month = period;
		} else if (day === null || period > day) {
			day = period;
		}
	}
	if (day !== null) return { day };
	return month === null ? null : { month };
}

const DAY_MS = 24 * 60 * 60 * 1000;

/*
 * The periods a "Last active" filter asks about, and whether a person must have a mark in one of them (`has`) or in
 * none (research R5). "Within N days" and "not within 30" are day marks, which live 40 days; "not within 90" can only
 * be told from month marks, and every month overlapping the window counts, so rounding never calls anyone inactive.
 */
export function lastActivePeriods(
	filter: LastActiveFilter,
	now: Date
): { periods: string[]; has: boolean } {
	if ('within' in filter) {
		return { periods: daysBack(filter.within, now), has: true };
	}
	if (filter.notWithin === 30) {
		return { periods: daysBack(30, now), has: false };
	}
	const months = new Set<string>();
	for (let i = 0; i < 90; i += 1) {
		months.add(monthOf(new Date(now.getTime() - i * DAY_MS)));
	}
	return { periods: [...months], has: false };
}

function daysBack(count: number, now: Date): string[] {
	return Array.from({ length: count }, (_, i) =>
		dayOf(new Date(now.getTime() - i * DAY_MS))
	);
}
