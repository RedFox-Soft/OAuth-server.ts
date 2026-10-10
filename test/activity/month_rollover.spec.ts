import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { closeEndedPeriods } from 'lib/activity/closer.ts';
import {
	atDay,
	figureOf,
	refresh,
	refreshTokenOf,
	seedBucket,
	seedUser,
	signInAndRedeem,
	startCounting
} from './fixtures.ts';

let bucketId: string;

/* An activity at `iso`: the clock is moved there for the duration of `action` only. */
async function at<T>(iso: string, action: () => Promise<T>): Promise<T> {
	const restore = atDay(iso);
	try {
		return await action();
	} finally {
		restore();
	}
}

/*
 * One bucket, and each case uses months no other case touches, so every figure read is the case's own and
 * can be asserted absolutely rather than as a difference.
 */

/**
 * @proves A month's figure is final once the month is over and stays as it was however much activity
 * follows, each UTC day counts its own people, and the UTC boundary decides which month a sign-in counts in.
 */
describe('active users across days and months', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'activity' });
		resetAdminMemoryStores();
		await startCounting();
		bucketId = await seedBucket('Activity rollover', ['act-rollover']);
	});

	it('reads a closed month as final and unchanged after activity in the next month', async () => {
		const first = await seedUser(bucketId);
		const second = await seedUser(bucketId);
		await at('2031-07-10T12:00:00Z', () =>
			signInAndRedeem('act-rollover', first)
		);
		const closed = await figureOf(
			bucketId,
			'2031-07',
			new Date('2031-08-01T01:00:00Z')
		);

		await at('2031-08-02T12:00:00Z', () =>
			signInAndRedeem('act-rollover', first)
		);
		await at('2031-08-02T13:00:00Z', () =>
			signInAndRedeem('act-rollover', second)
		);

		const later = await figureOf(
			bucketId,
			'2031-07',
			new Date('2031-09-15T00:00:00Z')
		);
		expect(closed).toMatchObject({ final: true, total: 1 });
		expect(later).toEqual(closed);
	});

	it('counts an end user active on two days once on each day and once in the month', async () => {
		const email = await seedUser(bucketId);

		await at('2031-09-03T08:00:00Z', () =>
			signInAndRedeem('act-rollover', email)
		);
		await at('2031-09-04T08:00:00Z', () =>
			signInAndRedeem('act-rollover', email)
		);

		const read = new Date('2031-09-04T09:00:00Z');
		expect((await figureOf(bucketId, '2031-09-03', read)).total).toBe(1);
		expect((await figureOf(bucketId, '2031-09-04', read)).total).toBe(1);
		expect((await figureOf(bucketId, '2031-09', read)).total).toBe(1);
	});

	it('counts an end user who signed in and later only refreshed once in the total and once under each kind', async () => {
		const email = await seedUser(bucketId);
		const tokens = await at('2031-10-05T08:00:00Z', () =>
			signInAndRedeem('act-rollover', email, { offline: true })
		);

		await at('2031-10-20T08:00:00Z', () =>
			refresh('act-rollover', refreshTokenOf(tokens))
		);

		const october = await figureOf(
			bucketId,
			'2031-10',
			new Date('2031-10-21T00:00:00Z')
		);
		expect(october).toMatchObject({
			total: 1,
			byKind: { local: 1, renewal: 1, federated: 0 }
		});
	});

	it("keeps a day's figure after its per-person records are gone when nobody read it in the meantime", async () => {
		const email = await seedUser(bucketId);
		await at('2032-01-10T08:00:00Z', () =>
			signInAndRedeem('act-rollover', email)
		);

		// The hourly pass, the day after; nobody opens the figures until long after the day's marks expired.
		await closeEndedPeriods(new Date('2032-01-11T01:00:00Z'));

		const read = new Date('2032-03-01T00:00:00Z');
		expect(await figureOf(bucketId, '2032-01-10', read)).toMatchObject({
			final: true,
			total: 1
		});
	});

	it('counts a sign-in a second before midnight UTC in that month, and one a second after in the next', async () => {
		const before = await seedUser(bucketId);
		const after = await seedUser(bucketId);

		await at('2031-11-30T23:59:59Z', () =>
			signInAndRedeem('act-rollover', before)
		);
		await at('2031-12-01T00:00:00Z', () =>
			signInAndRedeem('act-rollover', after)
		);

		const read = new Date('2031-12-01T00:10:00Z');
		expect((await figureOf(bucketId, '2031-11', read)).total).toBe(1);
		expect((await figureOf(bucketId, '2031-12', read)).total).toBe(1);
	});
});
