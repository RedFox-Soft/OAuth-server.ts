import { expiryOf, granularityOf } from '../../activity/periods.js';
import {
	SENTINEL_ID,
	figureId,
	freezeOpenPeriods,
	markId,
	periodsOf,
	tallyOf,
	tombstoneId,
	tombstoneOf
} from '../activity_records.js';
import type {
	ActivityBucketSnapshot,
	ActivityOwner,
	ActivityFigure,
	ActivityMarkInput,
	ActivityMarkRecord,
	ActivityStoreInstance,
	ActivityTally,
	ActivityTombstone
} from '../types.js';

/*
 * In-memory activity. Holds its own Maps rather than the shared `QuickLRU` storage the model adapter uses:
 * that store keeps at most a thousand entries, so marks would be evicted and the same person counted again
 * the next time they were active. Every write is a synchronous read-and-set with no `await` between, so
 * concurrent calls cannot interleave inside one.
 */
export class ActivityStore implements ActivityStoreInstance {
	private marks = new Map<string, ActivityMarkRecord>();
	private figuresById = new Map<string, ActivityFigure>();
	private tombstonesById = new Map<string, ActivityTombstone>();
	private sentinel = new Map<string, Date>();

	async mark(input: ActivityMarkInput): Promise<void> {
		for (const period of periodsOf(input.at)) {
			const id = markId(input.bucketId, period, input.accountId);
			const existing = this.marks.get(id);
			if (existing) {
				if (!existing.kinds.includes(input.kind))
					existing.kinds.push(input.kind);
				continue;
			}
			this.marks.set(id, {
				_id: id,
				bucketId: input.bucketId,
				period,
				granularity: granularityOf(period),
				accountId: input.accountId,
				kinds: [input.kind],
				provisioned: input.provisioned,
				expiresAt: expiryOf(period)
			});
		}
	}

	/* Expired marks are dropped on the way past, the lazy sweep the other bespoke memory stores do. */
	private live(period: string, at: Date): ActivityMarkRecord[] {
		const found: ActivityMarkRecord[] = [];
		for (const [id, mark] of this.marks) {
			if (mark.expiresAt.getTime() <= at.getTime()) {
				this.marks.delete(id);
			} else if (mark.period === period) {
				found.push(mark);
			}
		}
		return found;
	}

	async count(
		bucketId: string,
		period: string,
		at: Date
	): Promise<ActivityTally> {
		return tallyOf(
			this.live(period, at).filter((mark) => mark.bucketId === bucketId)
		);
	}

	async countPeriod(
		period: string,
		at: Date
	): Promise<Map<string, ActivityTally>> {
		const byBucket = new Map<string, ActivityMarkRecord[]>();
		for (const mark of this.live(period, at)) {
			const marks = byBucket.get(mark.bucketId) ?? [];
			marks.push(mark);
			byBucket.set(mark.bucketId, marks);
		}
		return new Map(
			[...byBucket].map(([bucketId, marks]) => [bucketId, tallyOf(marks)])
		);
	}

	async bucketsWithMarks(period: string, at: Date): Promise<string[]> {
		return [...new Set(this.live(period, at).map((mark) => mark.bucketId))];
	}

	async freeze(
		bucketId: string,
		period: string,
		bucket: Pick<ActivityBucketSnapshot, 'name' | 'slug'>,
		at: Date
	): Promise<ActivityFigure> {
		const id = figureId(bucketId, period);
		const stored = this.figuresById.get(id);
		if (stored) return structuredClone(stored);
		const figure: ActivityFigure = {
			_id: id,
			type: 'figure',
			bucketId,
			period,
			granularity: granularityOf(period),
			...tallyOf(
				this.live(period, at).filter((mark) => mark.bucketId === bucketId)
			),
			bucketName: bucket.name,
			...(bucket.slug === undefined ? {} : { bucketSlug: bucket.slug }),
			frozenAt: at
		};
		this.figuresById.set(id, figure);
		return structuredClone(figure);
	}

	async figure(
		bucketId: string,
		period: string
	): Promise<ActivityFigure | null> {
		const found = this.figuresById.get(figureId(bucketId, period));
		return found ? structuredClone(found) : null;
	}

	async figures(
		bucketId: string,
		granularity: 'month' | 'day',
		from: string,
		to: string
	): Promise<ActivityFigure[]> {
		return [...this.figuresById.values()]
			.filter(
				(figure) =>
					figure.bucketId === bucketId &&
					figure.granularity === granularity &&
					figure.period >= from &&
					figure.period <= to
			)
			.map((figure) => structuredClone(figure));
	}

	async figuresForPeriod(period: string): Promise<ActivityFigure[]> {
		return [...this.figuresById.values()]
			.filter((figure) => figure.period === period)
			.map((figure) => structuredClone(figure));
	}

	async retire(
		bucket: ActivityBucketSnapshot,
		owner: ActivityOwner,
		at: Date
	): Promise<void> {
		const tombstone = tombstoneOf(bucket, owner, at);
		if (!this.tombstonesById.has(tombstone._id)) {
			this.tombstonesById.set(tombstone._id, tombstone);
		}
		await freezeOpenPeriods(this, bucket, at);
	}

	async tombstone(bucketId: string): Promise<ActivityTombstone | null> {
		const found = this.tombstonesById.get(tombstoneId(bucketId));
		return found ? structuredClone(found) : null;
	}

	async tombstones(): Promise<ActivityTombstone[]> {
		return [...this.tombstonesById.values()].map((tombstone) =>
			structuredClone(tombstone)
		);
	}

	async countingSince(at: Date): Promise<Date> {
		if (!this.sentinel.has(SENTINEL_ID)) this.sentinel.set(SENTINEL_ID, at);
		return new Date(this.sentinel.get(SENTINEL_ID) ?? at);
	}
}
