import { sql } from './db.js';
import { docOf } from './json.js';
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

interface TallyRow {
	bucket: string;
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
	private marksArea: string = STORE_AREAS.activityMarks;
	private figuresArea: string = STORE_AREAS.activityFigures;

	/*
	 * One statement per period, atomic on the server: the insert writes the mark the first time, and on
	 * conflict the update appends this activity's kind unless the set already holds it. Containment
	 * (`@>`) rather than the `?` operator, which is also the placeholder character of other drivers and
	 * reads as a bug to anyone who has met one.
	 *
	 * The document is passed as an object, never `JSON.stringify(...)` (lib/adapters/postgres/json.ts).
	 */
	async mark(input: ActivityMarkInput): Promise<void> {
		const handle = sql();
		for (const period of periodsOf(input.at)) {
			const expiresAt = expiryOf(period);
			const record: ActivityMarkRecord = {
				_id: markId(input.bucketId, period, input.accountId),
				bucketId: input.bucketId,
				period,
				granularity: granularityOf(period),
				accountId: input.accountId,
				kinds: [input.kind],
				provisioned: input.provisioned,
				expiresAt
			};
			await handle`
				INSERT INTO ${handle(this.marksArea)} AS mark (id, doc, expires_at)
				VALUES (${record._id}, ${record}, ${expiresAt})
				ON CONFLICT (id) DO UPDATE
				SET doc = jsonb_set(mark.doc, '{kinds}', (mark.doc->'kinds') || jsonb_build_array(${input.kind}::text))
				WHERE NOT (mark.doc->'kinds' @> jsonb_build_array(${input.kind}::text))
			`;
		}
	}

	private async tallies(
		period: string,
		at: Date,
		bucketId?: string
	): Promise<TallyRow[]> {
		const handle = sql();
		let where = handle`doc->>'period' = ${period} AND expires_at > ${at}`;
		if (bucketId !== undefined) {
			where = handle`${where} AND doc->>'bucketId' = ${bucketId}`;
		}
		return handle<TallyRow[]>`
			SELECT doc->>'bucketId' AS bucket,
				count(*)::int AS total,
				(count(*) FILTER (WHERE doc->'kinds' @> '["local"]'::jsonb))::int AS local,
				(count(*) FILTER (WHERE doc->'kinds' @> '["federated"]'::jsonb))::int AS federated,
				(count(*) FILTER (WHERE doc->'kinds' @> '["renewal"]'::jsonb))::int AS renewal,
				(count(*) FILTER (WHERE (doc->>'provisioned')::boolean))::int AS provisioned
			FROM ${handle(this.marksArea)}
			WHERE ${where}
			GROUP BY doc->>'bucketId'
		`;
	}

	/* The sweeper runs once a minute, so a mark past its expiry may still be there; it is not counted. */
	async count(
		bucketId: string,
		period: string,
		at: Date
	): Promise<ActivityTally> {
		const [row] = await this.tallies(period, at, bucketId);
		return tallyFrom(row);
	}

	async countPeriod(
		period: string,
		at: Date
	): Promise<Map<string, ActivityTally>> {
		const rows = await this.tallies(period, at);
		return new Map(rows.map((row) => [row.bucket, tallyFrom(row)]));
	}

	async bucketsWithMarks(period: string, at: Date): Promise<string[]> {
		const handle = sql();
		const rows = await handle<{ bucket: string }[]>`
			SELECT DISTINCT doc->>'bucketId' AS bucket FROM ${handle(this.marksArea)}
			WHERE doc->>'period' = ${period} AND expires_at > ${at}
		`;
		return rows.map((row) => row.bucket);
	}

	async freeze(
		bucketId: string,
		period: string,
		bucket: Pick<ActivityBucketSnapshot, 'name' | 'slug'>,
		at: Date
	): Promise<ActivityFigure> {
		const existing = await this.figure(bucketId, period);
		if (existing) return existing;
		const figure: ActivityFigure = {
			_id: figureId(bucketId, period),
			type: 'figure',
			bucketId,
			period,
			granularity: granularityOf(period),
			...(await this.count(bucketId, period, at)),
			bucketName: bucket.name,
			...(bucket.slug === undefined ? {} : { bucketSlug: bucket.slug }),
			frozenAt: at
		};
		// Insert-if-absent: a concurrent freeze that got there first keeps its figure, and this one reads it.
		await this.insertIfAbsent(figure._id, figure);
		const stored = await this.figure(bucketId, period);
		if (!stored)
			throw new Error(`activity: figure ${figure._id} was not stored`);
		return stored;
	}

	/* By the marks' own ids, so the read is primary-key lookups and needs no index of its own. */
	async markedPeriods(
		bucketId: string,
		accountId: string,
		periods: readonly string[],
		at: Date
	): Promise<string[]> {
		if (periods.length === 0) return [];
		const handle = sql();
		const ids = periods.map((period) => markId(bucketId, period, accountId));
		const rows = await handle<{ period: string }[]>`
			SELECT doc->>'period' AS period FROM ${handle(this.marksArea)}
			WHERE id = ANY(${handle.array(ids, 'text')}) AND expires_at > ${at}
		`;
		const found = new Set(rows.map((row) => row.period));
		return periods.filter((period) => found.has(period));
	}

	/* One page of people's marks, on `{bucketId, accountId, period}` (specs/134 research R5). */
	async lastMarkedMany(
		bucketId: string,
		accountIds: readonly string[],
		at: Date
	): Promise<Map<string, LastMarked>> {
		const found = new Map<string, LastMarked>();
		if (accountIds.length === 0) return found;
		const handle = sql();
		const rows = await handle<{ accountId: string; period: string }[]>`
			SELECT doc->>'accountId' AS "accountId", doc->>'period' AS period
			FROM ${handle(this.marksArea)}
			WHERE doc->>'bucketId' = ${bucketId}
				AND doc->>'accountId' = ANY(${handle.array([...accountIds], 'text')})
				AND expires_at > ${at}
		`;
		const periods = new Map<string, string[]>();
		for (const row of rows) {
			const list = periods.get(row.accountId) ?? [];
			list.push(row.period);
			periods.set(row.accountId, list);
		}
		for (const [accountId, list] of periods) {
			const latest = latestMarked(list);
			if (latest) found.set(accountId, latest);
		}
		return found;
	}

	async accountsMarkedIn(
		bucketId: string,
		periods: readonly string[],
		at: Date
	): Promise<string[]> {
		if (periods.length === 0) return [];
		const handle = sql();
		const rows = await handle<{ accountId: string }[]>`
			SELECT DISTINCT doc->>'accountId' AS "accountId"
			FROM ${handle(this.marksArea)}
			WHERE doc->>'bucketId' = ${bucketId}
				AND doc->>'period' = ANY(${handle.array([...periods], 'text')})
				AND expires_at > ${at}
		`;
		return rows.map((row) => row.accountId);
	}

	private async insertIfAbsent(id: string, doc: object): Promise<void> {
		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.figuresArea)} (id, doc, expires_at)
			VALUES (${id}, ${doc}, NULL)
			ON CONFLICT (id) DO NOTHING
		`;
	}

	private async byId(id: string): Promise<unknown> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.figuresArea)} WHERE id = ${id}
		`;
		return rows[0] ? docOf(rows[0]) : undefined;
	}

	async figure(
		bucketId: string,
		period: string
	): Promise<ActivityFigure | null> {
		const found = await this.byId(figureId(bucketId, period));
		return found === undefined
			? null
			: documentOf(this.figuresArea, ActivityFigure, found);
	}

	async figures(
		bucketId: string,
		granularity: 'month' | 'day',
		from: string,
		to: string
	): Promise<ActivityFigure[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.figuresArea)}
			WHERE doc->>'type' = 'figure' AND doc->>'bucketId' = ${bucketId}
				AND doc->>'granularity' = ${granularity}
				AND doc->>'period' >= ${from} AND doc->>'period' <= ${to}
		`;
		return rows.map((row: unknown) =>
			documentOf(this.figuresArea, ActivityFigure, docOf(row))
		);
	}

	async figuresForPeriod(period: string): Promise<ActivityFigure[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.figuresArea)}
			WHERE doc->>'type' = 'figure' AND doc->>'period' = ${period}
		`;
		return rows.map((row: unknown) =>
			documentOf(this.figuresArea, ActivityFigure, docOf(row))
		);
	}

	async retire(
		bucket: ActivityBucketSnapshot,
		owner: ActivityOwner,
		at: Date
	): Promise<void> {
		const tombstone = tombstoneOf(bucket, owner, at);
		await this.insertIfAbsent(tombstone._id, tombstone);
		await freezeOpenPeriods(this, bucket, at);
	}

	async tombstone(bucketId: string): Promise<ActivityTombstone | null> {
		const found = await this.byId(tombstoneId(bucketId));
		return found === undefined
			? null
			: documentOf(this.figuresArea, ActivityTombstone, found);
	}

	async tombstones(): Promise<ActivityTombstone[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.figuresArea)} WHERE doc->>'type' = 'tombstone'
		`;
		return rows.map((row: unknown) =>
			documentOf(this.figuresArea, ActivityTombstone, docOf(row))
		);
	}

	async countingSince(at: Date): Promise<Date> {
		const sentinel: ActivitySentinel = {
			_id: SENTINEL_ID,
			type: 'sentinel',
			at
		};
		await this.insertIfAbsent(SENTINEL_ID, sentinel);
		return documentOf(
			this.figuresArea,
			ActivitySentinel,
			await this.byId(SENTINEL_ID)
		).at;
	}
}
