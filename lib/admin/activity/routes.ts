import { Elysia } from 'elysia';

import { getActivityStore, getBucketStore } from '../../adapters/index.js';
import type {
	ActivityBucketSnapshot,
	ActivityTombstone,
	UserBucket
} from '../../adapters/types.js';
import {
	type AdminContext,
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit } from '../buckets/access.js';
import { reservedOf } from '../consts.js';
import { now } from '../../activity/clock.js';
import {
	MONTH_PATTERN,
	daysOf,
	isClosable,
	monthOf,
	monthsBack,
	previousMonth
} from '../../activity/periods.js';
import {
	readPeriodForBuckets,
	readPeriods,
	type PeriodFigure,
	type PeriodForBuckets
} from '../../activity/read.js';
import {
	customerSummaries,
	instanceSummary,
	sharpChanges,
	type OverviewAnswer,
	type OverviewRow
} from '../../activity/overview.js';
import { resolveCustomers, UNKNOWN_CUSTOMER } from './customers.js';
import {
	ActivityOverviewQuery,
	ALLOWED_ACTIVITY_OVERVIEW_PARAMS,
	ALLOWED_BUCKET_ACTIVITY_PARAMS,
	BucketActivityQuery
} from './schema.js';

/*
 * Monthly and daily active users per bucket (specs/076): two reads, neither audited, because a count of how
 * many people were active is not a record of who — and no route here lists who.
 */

/* How many months a bucket's page shows: the month asked for and the twelve before it. */
const MONTHS_SHOWN = 13;

function assertNoUnknownParams(
	url: string,
	allowed: ReadonlySet<string>
): void {
	const unknown = [...new URL(url).searchParams.keys()].filter(
		(name) => !allowed.has(name)
	);
	if (unknown.length > 0) {
		throw new AdminError(
			422,
			`unknown query parameter: ${unknown.sort().join(', ')}`
		);
	}
}

/*
 * The month asked for, or the current one. A month in the future is refused rather than answered as zero:
 * a zero there would read as "nobody used it", which is a claim about a month that has not happened.
 */
function monthAsked(value: string | undefined, at: Date): string {
	if (value === undefined || value === '') return monthOf(at);
	if (!MONTH_PATTERN.test(value)) {
		throw new AdminError(422, 'month must be YYYY-MM');
	}
	if (value > monthOf(at)) {
		throw new AdminError(422, 'month must not be in the future');
	}
	return value;
}

function snapshotOf(bucket: UserBucket): ActivityBucketSnapshot {
	return {
		_id: bucket._id,
		name: bucket.name,
		...(bucket.slug === undefined ? {} : { slug: bucket.slug }),
		createdAt: bucket.createdAt
	};
}

function snapshotOfTombstone(
	tombstone: ActivityTombstone
): ActivityBucketSnapshot {
	return {
		_id: tombstone.bucketId,
		name: tombstone.bucketName,
		...(tombstone.bucketSlug === undefined
			? {}
			: { slug: tombstone.bucketSlug }),
		createdAt: tombstone.createdAt
	};
}

/*
 * The bucket whose figures are asked for. A super administrator may read any bucket's — the reserved ones
 * and deleted ones by their tombstones (specs/077) — because every one of those figures is already in their
 * overview; this only lets them look closer. Everyone else keeps the owning-group check, so a deleted
 * bucket stays unfindable to the group that owned it, as every other route answers it.
 */
async function bucketToRead(
	ctx: AdminContext,
	id: string
): Promise<ActivityBucketSnapshot> {
	if (!ctx.superAdmin) return snapshotOf(await loadBucketForEdit(ctx, id));
	const live = await getBucketStore().find(id);
	if (live) return snapshotOf(live);
	const tombstone = await getActivityStore().tombstone(id);
	if (tombstone) return snapshotOfTombstone(tombstone);
	/* A reserved bucket on an instance never provisioned: read as having always existed, as `bucketRefOf` does. */
	if (reservedOf(id) !== null)
		return { _id: id, name: id, createdAt: new Date(0) };
	throw new AdminError(404, 'bucket not found');
}

function present(figure: PeriodFigure | null): figure is PeriodFigure {
	return figure !== null;
}

export const activityRoutes = new Elysia({ name: 'admin-activity' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	/*
	 * One bucket's figures, for the group that owns it. The owning-group check rather than the broader one
	 * the bucket's detail page uses: a group that only owns a project signing into the bucket administers its
	 * users, not its plan. Both refuse a foreign bucket exactly as a missing one, and the administrators
	 * bucket to everyone but a super administrator, who may read any bucket's figures (`bucketToRead`).
	 */
	.get(
		'/admin/api/buckets/:id/activity',
		async ({ admin, params, query, request }) => {
			const ctx = assertAuth(admin);
			assertNoUnknownParams(request.url, ALLOWED_BUCKET_ACTIVITY_PARAMS);
			const bucket = await bucketToRead(ctx, params.id);
			const at = now();
			const month = monthAsked(query.month, at);

			const [months, days, since] = await Promise.all([
				readPeriods(bucket, monthsBack(month, MONTHS_SHOWN), at),
				readPeriods(bucket, daysOf(month, at), at),
				getActivityStore().countingSince(at)
			]);
			return {
				bucketId: bucket._id,
				countingSince: since.toISOString(),
				month: months[0] ?? null,
				days: days.filter(present),
				months: months.filter(present)
			};
		},
		{ query: BucketActivityQuery }
	)
	/*
	 * Every bucket on the instance, for a super administrator: the reserved ones, which the bucket list leaves
	 * out, and deleted ones, which no loader can find any more and which are listed from their tombstones.
	 *
	 * Since specs/077 it is the whole dashboard in one answer — each bucket's customer and thirteen months,
	 * the days of the month and of the month before, the customers' sums, the instance's totals and the
	 * buckets that changed sharply — all read at one instant. The console filters in the browser and
	 * recomputes the totals over what it shows with the same functions; the agent reads them as they are.
	 */
	.get(
		'/admin/api/activity',
		async ({ admin, query, request }): Promise<OverviewAnswer> => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			assertNoUnknownParams(request.url, ALLOWED_ACTIVITY_OVERVIEW_PARAMS);
			const at = now();
			const month = monthAsked(query.month, at);
			const previous = previousMonth(month);
			const monthLabels = monthsBack(month, MONTHS_SHOWN);
			const days = daysOf(month, at);
			const previousDays = daysOf(previous, at);

			const liveBuckets = await getBucketStore().list();
			const liveIds = new Set(liveBuckets.map((bucket) => bucket._id));
			const deleted = (await getActivityStore().tombstones()).filter(
				(tombstone) => !liveIds.has(tombstone.bucketId)
			);
			const everyBucket = [
				...liveBuckets.map((bucket) => ({
					bucket: snapshotOf(bucket),
					deletedAt: null,
					source: { bucketId: bucket._id, ownerGroupId: bucket.ownerGroupId }
				})),
				...deleted.map((tombstone) => ({
					bucket: snapshotOfTombstone(tombstone),
					deletedAt: tombstone.deletedAt.toISOString(),
					source: {
						bucketId: tombstone.bucketId,
						...(tombstone.ownerGroupId === undefined
							? {}
							: { ownerGroupId: tombstone.ownerGroupId }),
						...(tombstone.ownerLabel === undefined
							? {}
							: { recordedLabel: tombstone.ownerLabel })
					}
				}))
			];
			const buckets = everyBucket.map((entry) => entry.bucket);
			const read = (period: string) =>
				readPeriodForBuckets(buckets, period, at);

			const [monthReads, dayReads, previousDayReads, customers, since] =
				await Promise.all([
					Promise.all(monthLabels.map(read)),
					Promise.all(days.map(read)),
					Promise.all(previousDays.map(read)),
					resolveCustomers(everyBucket.map((entry) => entry.source)),
					getActivityStore().countingSince(at)
				]);
			const unavailable = new Set(
				[...monthReads, ...dayReads, ...previousDayReads].flatMap((reads) => [
					...reads.unavailable
				])
			);
			const totalOf = (reads: PeriodForBuckets, bucketId: string) =>
				unavailable.has(bucketId)
					? null
					: (reads.figures.get(bucketId)?.total ?? null);

			const rows: OverviewRow[] = everyBucket.map(({ bucket, deletedAt }) => {
				const lost = unavailable.has(bucket._id);
				const months = monthReads.map((reads) =>
					lost ? null : (reads.figures.get(bucket._id) ?? null)
				);
				return {
					bucketId: bucket._id,
					name: bucket.name,
					slug: bucket.slug ?? null,
					reserved: reservedOf(bucket._id),
					deleted: deletedAt,
					current: months[0] ?? null,
					previous: months[1] ?? null,
					customer: customers.refs.get(bucket._id) ?? UNKNOWN_CUSTOMER,
					months,
					days: dayReads.map((reads) => totalOf(reads, bucket._id)),
					previousDays: previousDayReads.map((reads) =>
						totalOf(reads, bucket._id)
					),
					unavailable: lost
				};
			});
			rows.sort(
				(a, b) =>
					Number(a.deleted !== null) - Number(b.deleted !== null) ||
					(b.current?.total ?? 0) - (a.current?.total ?? 0) ||
					a.name.localeCompare(b.name)
			);
			const monthClosed = isClosable(month, at);
			return {
				month,
				previous,
				asOf: at.toISOString(),
				countingSince: since.toISOString(),
				months: monthLabels,
				daysFinal: days.map((day) => isClosable(day, at)),
				buckets: rows,
				customers: customerSummaries(rows, customers.details),
				instance: instanceSummary(rows, MONTHS_SHOWN, month === monthOf(at)),
				changes: sharpChanges(rows, monthLabels, monthClosed ? 0 : 1)
			};
		},
		{ query: ActivityOverviewQuery }
	);
