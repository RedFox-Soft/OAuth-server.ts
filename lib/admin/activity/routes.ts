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
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit } from '../buckets/access.js';
import { heldDeletedBucket, holdsBucket } from '../auth/can.js';
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
 * overview; this only lets them look closer. Everyone else keeps the owning-group check, and since specs/091
 * the same check reaches a deleted bucket through the group its tombstone names: its active users counted in
 * that group's months, and the group's overview lists it. Anyone else falls through to the live loader, so a
 * deleted bucket is refused to them in exactly the words an id that never existed is.
 */
/* The bucket read, and — for a deleted one, which only a super administrator can reach — what its tombstone kept. */
interface BucketToRead {
	snapshot: ActivityBucketSnapshot;
	tombstone: ActivityTombstone | null;
}

async function bucketToRead(
	ctx: AdminContext,
	id: string
): Promise<BucketToRead> {
	if (!ctx.superAdmin) {
		if (!(await getBucketStore().find(id))) {
			const tombstone = await getActivityStore().tombstone(id);
			if (
				tombstone &&
				reservedOf(id) === null &&
				heldDeletedBucket(ctx, tombstone)
			) {
				return { snapshot: snapshotOfTombstone(tombstone), tombstone };
			}
		}
		return {
			snapshot: snapshotOf(await loadBucketForEdit(ctx, id)),
			tombstone: null
		};
	}
	const live = await getBucketStore().find(id);
	if (live) return { snapshot: snapshotOf(live), tombstone: null };
	const tombstone = await getActivityStore().tombstone(id);
	if (tombstone) return { snapshot: snapshotOfTombstone(tombstone), tombstone };
	/* A reserved bucket on an instance never provisioned: read as having always existed, as `bucketRefOf` does. */
	if (reservedOf(id) !== null)
		return {
			snapshot: { _id: id, name: id, createdAt: new Date(0) },
			tombstone: null
		};
	throw new AdminError(404, 'project not found');
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
	 * the bucket's detail page once used: figures are the owning group's, as the bucket itself is. Both refuse a foreign bucket exactly as a missing one, and the administrators
	 * bucket to everyone but a super administrator, who may read any bucket's figures (`bucketToRead`).
	 */
	.get(
		'/admin/api/projects/:id/activity',
		async ({ admin, params, query, request }) => {
			const ctx = assertAuth(admin);
			assertNoUnknownParams(request.url, ALLOWED_BUCKET_ACTIVITY_PARAMS);
			const { snapshot: bucket, tombstone } = await bucketToRead(
				ctx,
				params.id
			);
			const at = now();
			const month = monthAsked(query.month, at);

			const [months, days, since] = await Promise.all([
				readPeriods(bucket, monthsBack(month, MONTHS_SHOWN), at),
				readPeriods(bucket, daysOf(month, at), at),
				getActivityStore().countingSince(at)
			]);
			return {
				projectId: bucket._id,
				/*
				 * Named, and dated when deleted (specs/086), so a deleted bucket's history page can say what it was
				 * and when it went without a second read that no longer exists for it.
				 */
				name: bucket.name,
				deletedAt: tombstone ? tombstone.deletedAt.toISOString() : null,
				lastOwner:
					tombstone?.ownerGroupId !== undefined &&
					tombstone.ownerLabel !== undefined
						? { teamId: tombstone.ownerGroupId, label: tombstone.ownerLabel }
						: null,
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
	 * Since specs/091 every administrator reads it, over the buckets their groups hold and the deleted ones
	 * their groups held last — the buckets whose Activity tab each of them can already open. The set is
	 * narrowed before anything is read, so every figure, customer, contact, total and sharp change in the
	 * answer is computed from those buckets alone; no other tenant's number is ever summed into it.
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
			assertNoUnknownParams(request.url, ALLOWED_ACTIVITY_OVERVIEW_PARAMS);
			const at = now();
			const month = monthAsked(query.month, at);
			const previous = previousMonth(month);
			const monthLabels = monthsBack(month, MONTHS_SHOWN);
			const days = daysOf(month, at);
			const previousDays = daysOf(previous, at);

			/* The instance's own buckets belong to no administrator's group: a super administrator's alone. */
			const visible = (bucketId: string) =>
				ctx.superAdmin || reservedOf(bucketId) === null;
			const everyLive = await getBucketStore().list();
			const liveIds = new Set(everyLive.map((bucket) => bucket._id));
			const liveBuckets = everyLive.filter(
				(bucket) => visible(bucket._id) && holdsBucket(ctx, bucket)
			);
			const deleted = (await getActivityStore().tombstones()).filter(
				(tombstone) =>
					!liveIds.has(tombstone.bucketId) &&
					visible(tombstone.bucketId) &&
					heldDeletedBucket(ctx, tombstone)
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
					projectId: bucket._id,
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
				projects: rows,
				customers: customerSummaries(rows, customers.details),
				instance: instanceSummary(rows, MONTHS_SHOWN, month === monthOf(at)),
				changes: sharpChanges(rows, monthLabels, monthClosed ? 0 : 1)
			};
		},
		{ query: ActivityOverviewQuery }
	);
