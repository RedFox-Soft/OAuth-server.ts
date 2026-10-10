import { Elysia } from 'elysia';

import { getActivityStore, getBucketStore } from '../../adapters/index.js';
import type {
	ActivityBucketSnapshot,
	UserBucket
} from '../../adapters/types.js';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit } from '../buckets/access.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../consts.js';
import { now } from '../../activity/clock.js';
import {
	MONTH_PATTERN,
	daysOf,
	monthOf,
	monthsBack,
	previousMonth
} from '../../activity/periods.js';
import {
	readPeriodForBuckets,
	readPeriods,
	type PeriodFigure
} from '../../activity/read.js';
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

function present(figure: PeriodFigure | null): figure is PeriodFigure {
	return figure !== null;
}

function reservedOf(bucketId: string): 'default' | 'administrators' | null {
	if (bucketId === DEFAULT_BUCKET_ID) return 'default';
	if (bucketId === ADMIN_BUCKET_ID) return 'administrators';
	return null;
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
	 * bucket to everyone — its figure is in the overview, which is a super administrator's.
	 */
	.get(
		'/admin/api/buckets/:id/activity',
		async ({ admin, params, query, request }) => {
			const ctx = assertAuth(admin);
			assertNoUnknownParams(request.url, ALLOWED_BUCKET_ACTIVITY_PARAMS);
			const bucket = snapshotOf(await loadBucketForEdit(ctx, params.id));
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
	 */
	.get(
		'/admin/api/activity',
		async ({ admin, query, request }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			assertNoUnknownParams(request.url, ALLOWED_ACTIVITY_OVERVIEW_PARAMS);
			const at = now();
			const month = monthAsked(query.month, at);
			const previous = previousMonth(month);

			const live = (await getBucketStore().list()).map(snapshotOf);
			const liveIds = new Set(live.map((bucket) => bucket._id));
			const deleted = (await getActivityStore().tombstones())
				.filter((tombstone) => !liveIds.has(tombstone.bucketId))
				.map((tombstone) => ({
					bucket: {
						_id: tombstone.bucketId,
						name: tombstone.bucketName,
						...(tombstone.bucketSlug === undefined
							? {}
							: { slug: tombstone.bucketSlug }),
						createdAt: tombstone.createdAt
					},
					deletedAt: tombstone.deletedAt.toISOString()
				}));
			const everyBucket = [
				...live.map((bucket) => ({ bucket, deletedAt: null })),
				...deleted
			];
			const buckets = everyBucket.map((entry) => entry.bucket);
			const [current, before] = await Promise.all([
				readPeriodForBuckets(buckets, month, at),
				readPeriodForBuckets(buckets, previous, at)
			]);

			const rows = everyBucket.map(({ bucket, deletedAt }) => ({
				bucketId: bucket._id,
				name: bucket.name,
				slug: bucket.slug ?? null,
				reserved: reservedOf(bucket._id),
				deleted: deletedAt,
				current: current.get(bucket._id) ?? null,
				previous: before.get(bucket._id) ?? null
			}));
			rows.sort(
				(a, b) =>
					Number(a.deleted !== null) - Number(b.deleted !== null) ||
					(b.current?.total ?? 0) - (a.current?.total ?? 0) ||
					a.name.localeCompare(b.name)
			);
			return { month, previous, buckets: rows };
		},
		{ query: ActivityOverviewQuery }
	);
