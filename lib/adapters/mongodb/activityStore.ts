import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { expiryOf, granularityOf } from '../../activity/periods.js';
import {
	SENTINEL_ID,
	emptyTally,
	figureId,
	freezeOpenPeriods,
	latestMarked,
	markId,
	periodsOf,
	tombstoneId,
	tombstoneOf
} from '../activity_records.js';
import {
	ActivityFigure,
	ActivitySentinel,
	ActivityTombstone,
	type ActivityBucketSnapshot,
	type ActivityOwner,
	type ActivityMarkInput,
	type ActivityMarkRecord,
	type ActivityStoreInstance,
	type ActivityTally,
	type LastMarked
} from '../types.js';

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

type FiguresDocument = ActivityFigure | ActivityTombstone | ActivitySentinel;

/* The group stage both counts share: distinct accounts in total, per kind, and provisioned. */
const TALLY_GROUP = {
	total: { $sum: 1 },
	local: { $sum: { $cond: [{ $in: ['local', '$kinds'] }, 1, 0] } },
	federated: { $sum: { $cond: [{ $in: ['federated', '$kinds'] }, 1, 0] } },
	renewal: { $sum: { $cond: [{ $in: ['renewal', '$kinds'] }, 1, 0] } },
	provisioned: { $sum: { $cond: ['$provisioned', 1, 0] } }
};

interface TallyRow {
	_id: string;
	total: number;
	local: number;
	federated: number;
	renewal: number;
	provisioned: number;
}

function tallyFrom(row: TallyRow | undefined): ActivityTally {
	if (!row) return emptyTally();
	return {
		total: row.total,
		byKind: {
			local: row.local,
			federated: row.federated,
			renewal: row.renewal
		},
		provisioned: row.provisioned
	};
}

export class ActivityStore implements ActivityStoreInstance {
	private marks = db.collection<ActivityMarkRecord>(STORE_AREAS.activityMarks);
	private figuresArea = db.collection<FiguresDocument>(
		STORE_AREAS.activityFigures
	);

	/*
	 * `$setOnInsert` writes the mark the first time, `$addToSet` adds this activity's kind every time — one
	 * single-document operation, atomic on the server. Two concurrent first upserts of one `_id` can both
	 * try to insert; the loser gets duplicate key 11000, and its retry is then an update of the winner's
	 * document, which is the same idempotent operation.
	 */
	async mark(input: ActivityMarkInput): Promise<void> {
		for (const period of periodsOf(input.at)) {
			const id = markId(input.bucketId, period, input.accountId);
			const write = () =>
				this.marks.updateOne(
					{ _id: id },
					{
						$setOnInsert: {
							bucketId: input.bucketId,
							period,
							granularity: granularityOf(period),
							accountId: input.accountId,
							provisioned: input.provisioned,
							expiresAt: expiryOf(period)
						},
						$addToSet: { kinds: input.kind }
					},
					{ upsert: true }
				);
			try {
				await write();
			} catch (error) {
				if (!isDuplicateKey(error)) throw error;
				await write();
			}
		}
	}

	/* By the marks' own ids, so the read is primary-key lookups and needs no index of its own. */
	async markedPeriods(
		bucketId: string,
		accountId: string,
		periods: readonly string[],
		at: Date
	): Promise<string[]> {
		if (periods.length === 0) return [];
		const found = await this.marks
			.find(
				{
					_id: {
						$in: periods.map((period) => markId(bucketId, period, accountId))
					},
					expiresAt: { $gt: at }
				},
				{ projection: { period: 1 } }
			)
			.toArray();
		const marked = new Set(found.map((mark) => mark.period));
		return periods.filter((period) => marked.has(period));
	}

	/* One page of people's marks, on `{bucketId, accountId, period}` (specs/134 research R5). */
	async lastMarkedMany(
		bucketId: string,
		accountIds: readonly string[],
		at: Date
	): Promise<Map<string, LastMarked>> {
		const found = new Map<string, LastMarked>();
		if (accountIds.length === 0) return found;
		const marks = await this.marks
			.find(
				{
					bucketId,
					accountId: { $in: [...accountIds] },
					expiresAt: { $gt: at }
				},
				{ projection: { accountId: 1, period: 1 } }
			)
			.toArray();
		const periods = new Map<string, string[]>();
		for (const mark of marks) {
			const list = periods.get(mark.accountId) ?? [];
			list.push(mark.period);
			periods.set(mark.accountId, list);
		}
		for (const [accountId, list] of periods) {
			const latest = latestMarked(list);
			if (latest) found.set(accountId, latest);
		}
		return found;
	}

	/*
	 * The accounts with a live mark in any of `periods`, on `{bucketId, period}`: the users store's filter reads it. A
	 * `$group`, not `distinct`, which the strict Stable API v1 this server connects with does not offer.
	 */
	async accountsMarkedIn(
		bucketId: string,
		periods: readonly string[],
		at: Date
	): Promise<string[]> {
		const found = await this.marks
			.aggregate<{ _id: string }>([
				{
					$match: {
						bucketId,
						period: { $in: [...periods] },
						expiresAt: { $gt: at }
					}
				},
				{ $group: { _id: '$accountId' } }
			])
			.toArray();
		return found.map((entry) => entry._id);
	}

	private async tallies(match: Record<string, unknown>): Promise<TallyRow[]> {
		return this.marks
			.aggregate<TallyRow>([
				{ $match: match },
				{ $group: { _id: '$bucketId', ...TALLY_GROUP } }
			])
			.toArray();
	}

	/* The TTL monitor runs about once a minute, so a mark past its expiry may still be there; it is not counted. */
	async count(
		bucketId: string,
		period: string,
		at: Date
	): Promise<ActivityTally> {
		const [row] = await this.tallies({
			bucketId,
			period,
			expiresAt: { $gt: at }
		});
		return tallyFrom(row);
	}

	async countPeriod(
		period: string,
		at: Date
	): Promise<Map<string, ActivityTally>> {
		const rows = await this.tallies({ period, expiresAt: { $gt: at } });
		return new Map(rows.map((row) => [row._id, tallyFrom(row)]));
	}

	/*
	 * A `$group` rather than `distinct`: the client runs on the Stable API with `apiStrict` (db.ts), and
	 * `distinct` is not in API Version 1 — the server refuses it outright, which no in-memory test can show.
	 */
	async bucketsWithMarks(period: string, at: Date): Promise<string[]> {
		const rows = await this.marks
			.aggregate<{ _id: string }>([
				{ $match: { period, expiresAt: { $gt: at } } },
				{ $group: { _id: '$bucketId' } }
			])
			.toArray();
		return rows.map((row) => row._id);
	}

	async freeze(
		bucketId: string,
		period: string,
		bucket: Pick<ActivityBucketSnapshot, 'name' | 'slug'>,
		at: Date
	): Promise<ActivityFigure> {
		const id = figureId(bucketId, period);
		const existing = await this.figure(bucketId, period);
		if (existing) return existing;
		const tally = await this.count(bucketId, period, at);
		const figure: ActivityFigure = {
			_id: id,
			type: 'figure',
			bucketId,
			period,
			granularity: granularityOf(period),
			...tally,
			bucketName: bucket.name,
			...(bucket.slug === undefined ? {} : { bucketSlug: bucket.slug }),
			frozenAt: at
		};
		// Insert-if-absent: a concurrent freeze that got there first keeps its figure, and this one reads it.
		const { _id: _figureId, ...fields } = figure;
		await this.figuresArea
			.updateOne(
				{ _id: id },
				{ $setOnInsert: fields },
				{ upsert: true, ...ABSENT_UNDEFINED }
			)
			.catch((error: unknown) => {
				if (!isDuplicateKey(error)) throw error;
			});
		const stored = await this.figure(bucketId, period);
		if (!stored) throw new Error(`activity: figure ${id} was not stored`);
		return stored;
	}

	async figure(
		bucketId: string,
		period: string
	): Promise<ActivityFigure | null> {
		const found = await this.figuresArea.findOne({
			_id: figureId(bucketId, period)
		});
		return found
			? documentOf(STORE_AREAS.activityFigures, ActivityFigure, found)
			: null;
	}

	async figures(
		bucketId: string,
		granularity: 'month' | 'day',
		from: string,
		to: string
	): Promise<ActivityFigure[]> {
		const found = await this.figuresArea
			.find({
				type: 'figure',
				bucketId,
				granularity,
				period: { $gte: from, $lte: to }
			})
			.toArray();
		return found.map((document) =>
			documentOf(STORE_AREAS.activityFigures, ActivityFigure, document)
		);
	}

	async figuresForPeriod(period: string): Promise<ActivityFigure[]> {
		const found = await this.figuresArea
			.find({ type: 'figure', period })
			.toArray();
		return found.map((document) =>
			documentOf(STORE_AREAS.activityFigures, ActivityFigure, document)
		);
	}

	async retire(
		bucket: ActivityBucketSnapshot,
		owner: ActivityOwner,
		at: Date
	): Promise<void> {
		const { _id, ...fields } = tombstoneOf(bucket, owner, at);
		await this.figuresArea.updateOne(
			{ _id },
			{ $setOnInsert: fields },
			{ upsert: true, ...ABSENT_UNDEFINED }
		);
		await freezeOpenPeriods(this, bucket, at);
	}

	async tombstone(bucketId: string): Promise<ActivityTombstone | null> {
		const found = await this.figuresArea.findOne({
			_id: tombstoneId(bucketId)
		});
		return found
			? documentOf(STORE_AREAS.activityFigures, ActivityTombstone, found)
			: null;
	}

	async tombstones(): Promise<ActivityTombstone[]> {
		const found = await this.figuresArea.find({ type: 'tombstone' }).toArray();
		return found.map((document) =>
			documentOf(STORE_AREAS.activityFigures, ActivityTombstone, document)
		);
	}

	async countingSince(at: Date): Promise<Date> {
		await this.figuresArea
			.updateOne(
				{ _id: SENTINEL_ID },
				{ $setOnInsert: { type: 'sentinel', at } },
				{ upsert: true }
			)
			.catch((error: unknown) => {
				if (!isDuplicateKey(error)) throw error;
			});
		const found = await this.figuresArea.findOne({ _id: SENTINEL_ID });
		return documentOf(STORE_AREAS.activityFigures, ActivitySentinel, found).at;
	}
}
