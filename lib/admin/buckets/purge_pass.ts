import { getBucketStore } from '../../adapters/index.js';
import { now } from '../../activity/clock.js';
import { destroyBucket } from './destroy.js';

/*
 * Destroys every bucket whose thirty days of scheduled deletion have run out (specs/090 R11), and answers
 * how many it destroyed.
 *
 * Buckets are few, so the whole list is read rather than an index kept for this. Each due bucket is claimed
 * before anything happens to it, so a pass on another instance, or an administrator's Delete now, takes
 * none of the same work twice; a bucket that fails is logged and left for the next pass, which finds it
 * still scheduled once its claim lapses.
 *
 * The store is reached through its getter when a pass runs, never at import, for the reason
 * lib/activity/closer.ts gives.
 */
export async function purgeDueBuckets(at: Date = now()): Promise<number> {
	const due = (await getBucketStore().list()).filter(
		(bucket) =>
			bucket.deletion !== undefined &&
			bucket.deletion.purgeAt.getTime() <= at.getTime()
	);
	let destroyed = 0;
	for (const bucket of due) {
		try {
			const outcome = await destroyBucket(
				bucket,
				{ kind: 'server' },
				{ due: true, at }
			);
			if (!outcome.claimed) continue;
			destroyed += 1;
			if (outcome.failedAreas.length > 0) {
				console.error(
					'buckets: a scheduled bucket was destroyed, but records of its end-users survive',
					{ bucketId: bucket._id, failedAreas: outcome.failedAreas }
				);
			}
		} catch (error) {
			console.error(
				'buckets: destroying a scheduled bucket failed; the next pass will retry',
				{ bucketId: bucket._id, error }
			);
		}
	}
	return destroyed;
}

/*
 * Runs a pass every hour and returns the way to stop it — the pattern of `startCloser`: a failure is logged
 * and swallowed, since a timer's unhandled rejection would take the process with it, and the timer is
 * unreferenced, so it cannot hold a process open.
 */
export function startBucketPurger(
	intervalMs: number = 60 * 60 * 1000
): () => void {
	const timer = setInterval(() => {
		void purgeDueBuckets().catch((error: unknown) => {
			console.error(
				'buckets: the scheduled-deletion pass failed; the next pass will retry',
				error
			);
		});
	}, intervalMs);
	timer.unref();
	return () => clearInterval(timer);
}
