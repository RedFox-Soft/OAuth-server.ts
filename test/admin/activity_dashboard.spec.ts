import { describe, it, expect, beforeAll, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { activityRoutes } from 'lib/admin/activity/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { getActivityStore, getGroupStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import type { Group, User } from 'lib/adapters/types.ts';
import type { OverviewAnswer } from 'lib/activity/overview.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';
import { atDay, startCounting } from '../activity/fixtures.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(activityRoutes)
	.use(bucketRoutes);

/* Days of March 2031; the months before it are closed. */
const NOW = '2031-03-15T12:00:00Z';
let restoreClock: (() => void) | undefined;

let superAdmin: User;
let owner: User;
let member: User;
let team: Group;

/*
 * Through `app.handle` and a plain JSON parse rather than Eden: Eden revives any string that parses as a
 * date, which turns a period into a Date the console and an agent never see.
 */
async function overview(month?: string): Promise<OverviewAnswer> {
	const response = await app.handle(
		new Request(
			`http://e.ly/admin/api/activity${month ? `?month=${month}` : ''}`,
			{ headers: { cookie: await cookieFor(superAdmin) } }
		)
	);
	expect(response.status).toBe(200);
	return JSON.parse(await response.text()) as OverviewAnswer;
}

async function markMany(
	bucketId: string,
	count: number,
	iso: string,
	prefix = nanoid()
) {
	for (let i = 0; i < count; i += 1) {
		await getActivityStore().mark({
			bucketId,
			accountId: `${prefix}-${String(i)}`,
			kind: 'local',
			provisioned: false,
			at: new Date(iso)
		});
	}
}

async function bucketOf(groupId: string): Promise<string> {
	return (await bucketWithProjects(groupId, 0)).bucket._id;
}

async function deleteBucket(bucketId: string, as: User) {
	const response = await app.handle(
		new Request(`http://e.ly/admin/api/buckets/${bucketId}`, {
			method: 'DELETE',
			headers: { cookie: await cookieFor(as) }
		})
	);
	expect(response.status).toBeLessThan(300);
}

function rowOf(answer: OverviewAnswer, bucketId: string) {
	const row = answer.buckets.find((b) => b.bucketId === bucketId);
	if (!row) throw new Error(`no row for ${bucketId}`);
	return row;
}

/**
 * @proves A super administrator reading the usage overview sees, beside every bucket's active users, the
 * customer that owns it — by its current name, or by the name it had when a deleted bucket was deleted —
 * with the customer's owners as its contacts, its buckets summed, no change claimed for a month still in
 * progress, and the buckets that rose or fell sharply between two closed months.
 */
describe('the usage overview, for a super administrator', () => {
	beforeAll(async () => {
		await ensureAdminSeed();
		await startCounting();
		superAdmin = await createAdministrator('super');
		owner = await createAdministrator('plain');
		member = await createAdministrator('plain');
		team = await regularGroup([owner], [member]);
	});

	afterEach(() => {
		restoreClock?.();
		restoreClock = undefined;
	});

	it('names each bucket by its customer — a regular group by its name, a personal group as Personal and its owner, a reserved bucket as System', async () => {
		const personal = await ensurePersonalGroup(owner._id, owner.email);
		const teamBucket = await bucketOf(team._id);
		const personalBucket = await bucketOf(personal._id);
		restoreClock = atDay(NOW);

		const answer = await overview();

		expect(rowOf(answer, teamBucket).customer.label).toBe(team.name);
		expect(rowOf(answer, personalBucket).customer.label).toBe(
			`Personal — ${owner.email}`
		);
		expect(rowOf(answer, DEFAULT_BUCKET_ID).customer.label).toBe('System');
		expect(rowOf(answer, ADMIN_BUCKET_ID).customer.label).toBe('System');
	});

	it('shows a renamed group by its new name', async () => {
		const group = await regularGroup([owner]);
		const bucketId = await bucketOf(group._id);
		await getGroupStore().update(group._id, { name: 'Renamed Ltd' });
		restoreClock = atDay(NOW);

		const answer = await overview();

		expect(rowOf(answer, bucketId).customer.label).toBe('Renamed Ltd');
	});

	it('lists a deleted bucket under the customer that owned it when it was deleted', async () => {
		const group = await regularGroup([owner]);
		const bucketId = await bucketOf(group._id);
		await markMany(bucketId, 3, '2031-03-02T09:00:00Z');
		restoreClock = atDay(NOW);
		await deleteBucket(bucketId, owner);

		const row = rowOf(await overview(), bucketId);

		expect(row.deleted).not.toBeNull();
		expect(row.customer).toMatchObject({
			groupId: group._id,
			label: group.name
		});
	});

	it('reads a bucket deleted before owners were recorded as an unknown customer', async () => {
		const bucketId = `pre-077-${nanoid().toLowerCase()}`;
		const store = getActivityStore();
		const stored = store.tombstones.bind(store);
		/* The tombstone exactly as spec 076 wrote it, before an owner was kept. */
		const listed = spyOn(store, 'tombstones').mockImplementation(async () => [
			...(await stored()),
			{
				_id: `bucket|${bucketId}`,
				type: 'tombstone',
				bucketId,
				bucketName: 'old bucket',
				createdAt: new Date(0),
				deletedAt: new Date('2031-01-05T00:00:00Z')
			}
		]);
		restoreClock = atDay(NOW);

		const row = await overview()
			.then((answer) => rowOf(answer, bucketId))
			.finally(() => listed.mockRestore());

		expect(row.customer).toEqual({
			groupId: null,
			label: 'Unknown',
			kind: null,
			exists: false
		});
	});

	it("lists a customer's owners as its contacts, not its plain members", async () => {
		const bucketId = await bucketOf(team._id);
		restoreClock = atDay(NOW);

		const answer = await overview();
		const customer = answer.customers.find((c) =>
			c.bucketIds.includes(bucketId)
		);

		expect(customer?.contacts).toContain(owner.email);
		expect(customer?.contacts).not.toContain(member.email);
	});

	it("sums a customer's buckets, a deleted one included", async () => {
		const group = await regularGroup([owner]);
		const kept = await bucketOf(group._id);
		const gone = await bucketOf(group._id);
		await markMany(kept, 10, '2031-03-03T09:00:00Z');
		await markMany(gone, 15, '2031-03-04T09:00:00Z');
		restoreClock = atDay(NOW);
		await deleteBucket(gone, owner);

		const customer = (await overview()).customers.find(
			(c) => c.customer.groupId === group._id
		);

		expect(customer?.current?.total).toBe(25);
		expect(customer?.bucketIds.sort()).toEqual([kept, gone].sort());
	});

	it('carries no change against the previous month while the month is in progress', async () => {
		restoreClock = atDay(NOW);

		const answer = await overview();

		expect(answer.instance.months[0]?.final).toBe(false);
		expect(answer.instance.change).toBeNull();
	});

	it('shows the change against the previous month once both are closed', async () => {
		restoreClock = atDay(NOW);

		const answer = await overview('2031-02');

		expect(answer.instance.change).not.toBeNull();
	});

	describe('sharp changes between closed months', () => {
		let fell: string;
		let rose: string;
		let small: string;

		beforeAll(async () => {
			const group = await regularGroup([owner]);
			fell = await bucketOf(group._id);
			rose = await bucketOf(group._id);
			small = await bucketOf(group._id);
			await markMany(fell, 200, '2031-01-10T09:00:00Z');
			await markMany(fell, 50, '2031-02-10T09:00:00Z');
			await markMany(rose, 100, '2031-01-10T09:00:00Z');
			await markMany(rose, 300, '2031-02-10T09:00:00Z');
			await markMany(small, 3, '2031-01-10T09:00:00Z');
			await markMany(small, 1, '2031-02-10T09:00:00Z');
		});

		it('lists a bucket that fell sharply, with its customer', async () => {
			restoreClock = atDay(NOW);

			const { changes } = await overview('2031-02');
			const fall = changes.falls.find((c) => c.bucketId === fell);

			expect(fall).toMatchObject({
				from: { period: '2031-01', total: 200 },
				to: { period: '2031-02', total: 50 },
				absolute: -150,
				percent: -75
			});
			expect(fall?.customer.label).toBeTruthy();
			expect(changes.rises.map((c) => c.bucketId)).toContain(rose);
		});

		it('does not list a change among a handful of people', async () => {
			restoreClock = atDay(NOW);

			const { changes } = await overview('2031-02');

			expect(
				[...changes.falls, ...changes.rises].map((c) => c.bucketId)
			).not.toContain(small);
		});

		it('compares the last two closed months while the month asked for is in progress', async () => {
			restoreClock = atDay(NOW);

			const { changes } = await overview();

			expect(changes).toMatchObject({ from: '2031-01', to: '2031-02' });
			expect(changes.falls.map((c) => c.bucketId)).toContain(fell);
		});
	});
});
