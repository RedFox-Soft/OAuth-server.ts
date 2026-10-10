import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import { ActivityStore } from 'lib/adapters/memory/activityStore.ts';
import { ACTIVITY_KINDS, type ActivityKind } from 'lib/adapters/types.ts';
import { dayOf, endOf, expiryOf, monthOf } from 'lib/activity/periods.ts';

/*
 * Each case builds its own store rather than using the process-wide one: these cases move time months
 * forward, and a shared store would let that reach other suites' marks.
 */

const BUCKET = 'retention-bucket';
const SNAPSHOT = { name: 'Retention' };

/* An instant in a fixed month, so every generated activity lands in one period. */
const IN_MONTH = Date.UTC(2026, 3, 1);
const MONTH = monthOf(new Date(IN_MONTH));
const MONTH_LENGTH_MS = endOf(MONTH).getTime() - IN_MONTH;
const AFTER_MONTH = new Date(endOf(MONTH).getTime() + 10 * 60 * 1000);

const activity = fc.record({
	account: fc.constantFrom('a', 'b', 'c', 'd', 'e', 'f'),
	kind: fc.constantFrom<ActivityKind>(...ACTIVITY_KINDS),
	offset: fc.integer({ min: 0, max: MONTH_LENGTH_MS - 1 }),
	provisioned: fc.boolean()
});
const activities = fc.array(activity, { maxLength: 40 });

type Activity = {
	account: string;
	kind: ActivityKind;
	offset: number;
	provisioned: boolean;
};

async function replay(store: ActivityStore, sequence: readonly Activity[]) {
	for (const one of sequence) {
		await store.mark({
			bucketId: BUCKET,
			accountId: one.account,
			kind: one.kind,
			provisioned: one.provisioned,
			at: new Date(IN_MONTH + one.offset)
		});
	}
}

/**
 * @proves A closed period's figure is exactly the number of distinct people active in it, never changes
 * once recorded, and outlives the per-person records it was counted from, which are gone thirteen months
 * after a month and forty days after a day.
 */
describe('activity figures and the records they are counted from', () => {
	it('counts every distinct account once in a closed period, in total and per kind', async () => {
		await fc.assert(
			fc.asyncProperty(activities, async (sequence) => {
				const store = new ActivityStore();
				await replay(store, sequence);

				const figure = await store.freeze(BUCKET, MONTH, SNAPSHOT, AFTER_MONTH);

				expect(figure.total).toBe(
					new Set(sequence.map((one) => one.account)).size
				);
				for (const kind of ACTIVITY_KINDS) {
					const withKind = sequence.filter((one) => one.kind === kind);
					expect(figure.byKind[kind]).toBe(
						new Set(withKind.map((one) => one.account)).size
					);
				}
			})
		);
	});

	it('returns the figure first recorded when a period is closed again after more activity', async () => {
		await fc.assert(
			fc.asyncProperty(activities, activities, async (before, after) => {
				const store = new ActivityStore();
				await replay(store, before);
				const first = await store.freeze(BUCKET, MONTH, SNAPSHOT, AFTER_MONTH);
				await replay(store, after);

				const again = await store.freeze(BUCKET, MONTH, SNAPSHOT, AFTER_MONTH);

				expect(again).toEqual(first);
			})
		);
	});

	it('keeps no record linking an account to a month thirteen months after it ends, while its figure remains', async () => {
		const store = new ActivityStore();
		await store.mark({
			bucketId: BUCKET,
			accountId: 'gone',
			kind: 'local',
			provisioned: false,
			at: new Date(IN_MONTH)
		});
		const figure = await store.freeze(BUCKET, MONTH, SNAPSHOT, AFTER_MONTH);

		const later = expiryOf(MONTH);

		expect(await store.bucketsWithMarks(MONTH, later)).toEqual([]);
		expect((await store.count(BUCKET, MONTH, later)).total).toBe(0);
		expect(await store.figure(BUCKET, MONTH)).toEqual(figure);
	});

	it('keeps no record of who was active on a day forty days after it ends, while its figure remains', async () => {
		const store = new ActivityStore();
		const day = dayOf(new Date(IN_MONTH));
		await store.mark({
			bucketId: BUCKET,
			accountId: 'gone',
			kind: 'local',
			provisioned: false,
			at: new Date(IN_MONTH)
		});
		const figure = await store.freeze(BUCKET, day, SNAPSHOT, AFTER_MONTH);

		const later = expiryOf(day);

		expect(await store.bucketsWithMarks(day, later)).toEqual([]);
		expect(await store.figure(BUCKET, day)).toEqual(figure);
	});
});
