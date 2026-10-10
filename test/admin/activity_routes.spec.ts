import { describe, it, expect, beforeAll, afterEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { activityRoutes } from 'lib/admin/activity/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getActivityStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import type { User } from 'lib/adapters/types.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';
import { answered } from './answered.ts';
import { atDay, startCounting } from '../activity/fixtures.ts';

const app = new Elysia().use(resolveAdmin).use(activityRoutes);
const client = treaty(app);

const NOW = '2031-03-15T12:00:00Z';
let restoreClock: (() => void) | undefined;

let owner: User;
let foreigner: User;
let superAdmin: User;
let bucketId: string;

async function mark(accountId: string, iso: string) {
	await getActivityStore().mark({
		bucketId,
		accountId,
		kind: 'local',
		provisioned: false,
		at: new Date(iso)
	});
}

/*
 * Through `app.handle` and a plain JSON parse rather than Eden: Eden revives any string that parses as a date,
 * which turns a day's period — `2031-03-15` — into a Date the console and an agent never see.
 */
interface DayOrMonth {
	period: string;
	final: boolean;
	total: number;
}
interface BucketActivityBody {
	month: DayOrMonth | null;
	days: DayOrMonth[];
	months: DayOrMonth[];
}

async function bucketActivity(
	id: string,
	cookie: string,
	query: Record<string, string> = {}
) {
	const search = new URLSearchParams(query).toString();
	const response = await app.handle(
		new Request(
			`http://e.ly/admin/api/buckets/${encodeURIComponent(id)}/activity${search ? `?${search}` : ''}`,
			{ headers: { cookie } }
		)
	);
	const text = await response.text();
	return {
		status: response.status,
		text,
		body: JSON.parse(text) as BucketActivityBody
	};
}

/**
 * @proves An administrator reads the monthly and daily active users of a bucket their group owns, and
 * nothing of anyone else's; a super administrator reads every bucket on the instance at once; and a
 * figure is a count, never a list of who.
 */
describe('reading active users', () => {
	beforeAll(async () => {
		await ensureAdminSeed();
		await startCounting();
		owner = await createAdministrator(
			'plain',
			`activity-owner-${Math.random()}@x.io`
		);
		foreigner = await createAdministrator(
			'plain',
			`activity-foreign-${Math.random()}@x.io`
		);
		superAdmin = await createAdministrator(
			'super',
			`activity-super-${Math.random()}@x.io`
		);
		const group = await regularGroup([owner]);
		bucketId = (await bucketWithProjects(group._id, 0)).bucket._id;
		await mark('activity-account-a', '2031-02-10T09:00:00Z');
		await mark('activity-account-b', '2031-02-11T09:00:00Z');
		await mark('activity-account-a', '2031-03-14T09:00:00Z');
	});

	afterEach(() => {
		restoreClock?.();
		restoreClock = undefined;
	});

	it("gives a member of the owning group the bucket's month, its days and the previous months", async () => {
		restoreClock = atDay(NOW);
		const cookie = await cookieFor(owner);

		const res = await bucketActivity(bucketId, cookie);

		expect(res.status).toBe(200);
		const { body } = res;
		expect(body.month).toMatchObject({
			period: '2031-03',
			final: false,
			total: 1
		});
		expect(body.days.at(-1)).toMatchObject({ period: '2031-03-15', total: 0 });
		expect(body.days.find((day) => day.period === '2031-03-14')).toMatchObject({
			total: 1
		});
		expect(body.months.map((month) => month.period).slice(0, 2)).toEqual([
			'2031-03',
			'2031-02'
		]);
		expect(body.months[1]).toMatchObject({ final: true, total: 2 });
	});

	it("refuses a foreign bucket's figures with the answer given for a bucket that does not exist", async () => {
		restoreClock = atDay(NOW);
		const cookie = await cookieFor(foreigner);

		const foreign = await bucketActivity(bucketId, cookie);
		const missing = await bucketActivity('no-such-bucket', cookie);

		expect(foreign.status).toBe(403);
		expect(foreign.status).toBe(missing.status);
		expect(foreign.text).toEqual(missing.text);
	});

	it('lists every bucket in the overview, the default and administrators buckets included', async () => {
		restoreClock = atDay(NOW);

		const res = await client.admin.api.activity.get({
			headers: { cookie: await cookieFor(superAdmin) }
		});

		expect(res.status).toBe(200);
		const body = answered(res.data);
		expect(body).toMatchObject({ month: '2031-03', previous: '2031-02' });
		const ids = body.buckets.map((row) => row.bucketId);
		expect(ids).toContain(DEFAULT_BUCKET_ID);
		expect(ids).toContain(ADMIN_BUCKET_ID);
		expect(body.buckets.find((row) => row.bucketId === bucketId)).toMatchObject(
			{
				current: { total: 1 },
				previous: { total: 2, final: true }
			}
		);
	});

	it('refuses the overview to an administrator who is not a super administrator', async () => {
		const res = await client.admin.api.activity.get({
			headers: { cookie: await cookieFor(owner) }
		});

		expect(res.status).toBe(403);
	});

	it('answers counts and no account identifier, email address or name', async () => {
		restoreClock = atDay(NOW);

		const own = await bucketActivity(bucketId, await cookieFor(owner));
		const all = await client.admin.api.activity.get({
			headers: { cookie: await cookieFor(superAdmin) }
		});

		const serialised = JSON.stringify([own.body, all.data]);
		expect(serialised).not.toContain('activity-account-a');
		expect(serialised).not.toContain('activity-account-b');
		expect(serialised).not.toContain(owner.email);
	});

	it('refuses a malformed month with 422', async () => {
		const res = await bucketActivity(bucketId, await cookieFor(owner), {
			month: '2031-3'
		});

		expect(res.status).toBe(422);
	});

	it('refuses a month in the future with 422', async () => {
		restoreClock = atDay(NOW);

		const res = await bucketActivity(bucketId, await cookieFor(owner), {
			month: '2031-04'
		});

		expect(res.status).toBe(422);
	});

	it('refuses an unknown query parameter with 422', async () => {
		const res = await bucketActivity(bucketId, await cookieFor(owner), {
			mont: '2031-03'
		});

		expect(res.status).toBe(422);
	});

	it('answers a month before the bucket existed as absent', async () => {
		const res = await bucketActivity(bucketId, await cookieFor(owner), {
			month: '2020-01'
		});

		expect(res.status).toBe(200);
		const { body } = res;
		expect(body.month).toBeNull();
		expect(body.months).toEqual([]);
	});

	it('answers a closed month with no activity since the bucket was created as zero', async () => {
		restoreClock = atDay(NOW);

		const res = await bucketActivity(bucketId, await cookieFor(owner), {
			month: '2031-01'
		});

		expect(res.body.month).toMatchObject({ final: true, total: 0 });
	});
});
