import { getActivityStore, getBucketStore } from '../adapters/index.js';
import type {
	ActivityBucketSnapshot,
	ActivityTally
} from '../adapters/types.js';
import { now } from './clock.js';
import { emptyTally } from '../adapters/activity_records.js';
import { endOf, expiryOf, isClosable } from './periods.js';

export type PeriodFigure = ActivityTally & { period: string; final: boolean };

/*
 * The bucket a figure belongs to, as a reader needs it: the live record, or the tombstone of a deleted one.
 * Neither exists for a reserved bucket on an instance that was never provisioned (a test, mostly); it is then
 * read as having always existed, which is what a reserved bucket is.
 */
export async function bucketRefOf(
	bucketId: string
): Promise<ActivityBucketSnapshot> {
	const live = await getBucketStore().find(bucketId);
	if (live) {
		return {
			_id: live._id,
			name: live.name,
			...(live.slug === undefined ? {} : { slug: live.slug }),
			createdAt: live.createdAt
		};
	}
	const tombstone = await getActivityStore().tombstone(bucketId);
	if (tombstone) {
		return {
			_id: bucketId,
			name: tombstone.bucketName,
			...(tombstone.bucketSlug === undefined
				? {}
				: { slug: tombstone.bucketSlug }),
			createdAt: tombstone.createdAt
		};
	}
	return { _id: bucketId, name: bucketId, createdAt: new Date(0) };
}

/*
 * What a reader is shown for each period, per the state table in data-model.md:
 *
 * - before the bucket existed, or before counting began: absent (`null`), never zero (FR-015);
 * - open, or ended within the grace: counted live from the marks, not final;
 * - ended and frozen: the stored figure, final;
 * - ended and not yet frozen: frozen now, then as above — a reader never sees a closed period as not final;
 * - ended with no marks: zero and final, computed rather than stored, so viewing a quiet month writes nothing.
 *
 * A period whose marks have already expired unfrozen can no longer be counted; it reads as zero. The closer
 * runs hourly and marks live forty days or more, so this is a period no instance was running to close.
 */
export async function readPeriods(
	bucket: ActivityBucketSnapshot,
	periods: readonly string[],
	at: Date = now()
): Promise<(PeriodFigure | null)[]> {
	const store = getActivityStore();
	const since = await store.countingSince(at);
	const start = Math.max(bucket.createdAt.getTime(), since.getTime());

	return Promise.all(
		periods.map(async (period): Promise<PeriodFigure | null> => {
			if (endOf(period).getTime() <= start) return null;
			/*
			 * A stored figure is final whenever it exists — an open period has one only when its bucket was
			 * deleted, and then nobody can be active in it again.
			 */
			const stored = await store.figure(bucket._id, period);
			if (stored) return { period, final: true, ...tallyOfFigure(stored) };
			if (!isClosable(period, at)) {
				return {
					period,
					final: false,
					...(await store.count(bucket._id, period, at))
				};
			}
			if (at.getTime() >= expiryOf(period).getTime()) {
				return { period, final: true, ...emptyTally() };
			}
			const counted = await store.count(bucket._id, period, at);
			if (counted.total === 0) return { period, final: true, ...counted };
			const frozen = await store.freeze(bucket._id, period, bucket, at);
			return { period, final: true, ...tallyOfFigure(frozen) };
		})
	);
}

export async function readPeriod(
	bucketId: string,
	period: string,
	at: Date = now()
): Promise<PeriodFigure | null> {
	const [figure] = await readPeriods(await bucketRefOf(bucketId), [period], at);
	return figure ?? null;
}

function tallyOfFigure(figure: ActivityTally): ActivityTally {
	return {
		total: figure.total,
		byKind: { ...figure.byKind },
		provisioned: figure.provisioned
	};
}

/*
 * One period across many buckets, for the instance overview: one count or one figure listing for the period
 * rather than a read per bucket. A bucket whose ended period is unfrozen and has marks falls back to the
 * single-bucket read, which freezes it — rare, since the closer runs hourly.
 */
export async function readPeriodForBuckets(
	buckets: readonly ActivityBucketSnapshot[],
	period: string,
	at: Date = now()
): Promise<Map<string, PeriodFigure | null>> {
	const store = getActivityStore();
	const since = (await store.countingSince(at)).getTime();
	const existed = (bucket: ActivityBucketSnapshot) =>
		endOf(period).getTime() > Math.max(bucket.createdAt.getTime(), since);
	const answers = new Map<string, PeriodFigure | null>();

	/* Final wherever stored, for the reason readPeriods gives: a deleted bucket's open period is frozen. */
	const figures = new Map(
		(await store.figuresForPeriod(period)).map((figure) => [
			figure.bucketId,
			figure
		])
	);

	if (!isClosable(period, at)) {
		const counts = await store.countPeriod(period, at);
		for (const bucket of buckets) {
			const figure = figures.get(bucket._id);
			answers.set(
				bucket._id,
				!existed(bucket)
					? null
					: figure
						? { period, final: true, ...tallyOfFigure(figure) }
						: {
								period,
								final: false,
								...(counts.get(bucket._id) ?? emptyTally())
							}
			);
		}
		return answers;
	}

	const withMarks = new Set(await store.bucketsWithMarks(period, at));
	for (const bucket of buckets) {
		if (!existed(bucket)) {
			answers.set(bucket._id, null);
			continue;
		}
		const figure = figures.get(bucket._id);
		if (figure) {
			answers.set(bucket._id, {
				period,
				final: true,
				...tallyOfFigure(figure)
			});
		} else if (!withMarks.has(bucket._id)) {
			answers.set(bucket._id, { period, final: true, ...emptyTally() });
		} else {
			const [read] = await readPeriods(bucket, [period], at);
			answers.set(bucket._id, read ?? null);
		}
	}
	return answers;
}
