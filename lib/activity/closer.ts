import { getActivityStore } from '../adapters/index.js';
import { now } from './clock.js';
import {
	dayOf,
	expiryOf,
	isClosable,
	monthOf,
	previousMonth
} from './periods.js';
import { bucketRefOf } from './read.js';

/*
 * Freezes the figure of every period that has ended, so a closed month or day has a final figure whether or
 * not anybody reads it before its marks expire (specs/076, research R5).
 *
 * The work list is not "every unfrozen period": that would scan thirteen months of marks every hour. It is
 * the periods whose marks can still be counted and which may have ended since — the previous month, and the
 * last forty days — each asked for the buckets that have marks in it. A freeze is insert-if-absent, so a
 * period another instance, a reader or a bucket deletion already froze is left exactly as it is.
 *
 * Every store is reached through its getter when a pass runs, never at import: this module is started from
 * the application's entry, and an import of the adapter module from here at load would be the cycle
 * wiki/concepts/model-graph-import-order.md warns about.
 */
export async function closeEndedPeriods(at: Date = now()): Promise<number> {
	const store = getActivityStore();
	let frozen = 0;
	for (const period of candidatePeriods(at)) {
		if (!isClosable(period, at) || at.getTime() >= expiryOf(period).getTime()) {
			continue;
		}
		for (const bucketId of await store.bucketsWithMarks(period, at)) {
			if (await store.figure(bucketId, period)) continue;
			await store.freeze(bucketId, period, await bucketRefOf(bucketId), at);
			frozen += 1;
		}
	}
	return frozen;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const DAYS_BACK = 41;

function candidatePeriods(at: Date): string[] {
	const month = monthOf(at);
	const days = Array.from({ length: DAYS_BACK }, (_, back) =>
		dayOf(new Date(at.getTime() - back * DAY_MS))
	);
	return [previousMonth(month), month, ...days];
}

/*
 * Runs a pass every hour and returns the way to stop it. A failure is logged and swallowed — the next pass
 * tries again, and a timer's unhandled rejection would take the process with it — and the timer is
 * unreferenced, so it cannot hold a process open. The pattern of lib/adapters/postgres/reap.ts.
 */
export function startCloser(intervalMs: number = 60 * 60 * 1000): () => void {
	const timer = setInterval(() => {
		void closeEndedPeriods().catch((error: unknown) => {
			console.error(
				'activity: closing ended periods failed; the next pass will retry',
				error
			);
		});
	}, intervalMs);
	timer.unref();
	return () => clearInterval(timer);
}
