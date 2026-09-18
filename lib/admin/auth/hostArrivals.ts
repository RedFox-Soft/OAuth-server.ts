import { getBucketStore } from '../../adapters/index.js';

/*
 * Recording that a request reached a bucket's hostname — the one thing this server can honestly say
 * about whether an address works.
 *
 * Three properties are load-bearing, and each is a way this could go wrong instead of being useful.
 *
 * **It is never a write per request.** Resolution runs on every request to a host-addressed bucket, so
 * a write there would put a datastore round trip on the hot path of every tenant. The debounce below
 * bounds it to one write per host per window, which is all the granularity an operator needs: the
 * question is "has anything ever arrived, and roughly when last", not "how many".
 *
 * **It never delays a response and never fails a request.** Not awaited by its caller, and its own
 * failure is swallowed — the principle `lib/error_store/capture.ts` already establishes for recording
 * faults. An arrival record that could 500 a sign-in would be worse than no arrival record.
 *
 * **It records observation, not verification.** "A request arrived at this host" either happened or it
 * did not. A stored claim that a name resolves here, or that a certificate is valid, would be asserted
 * once and believed long after it stopped being true — see the field comments on `UserBucket`.
 */

/* Long enough that a busy tenant writes twice an hour rather than thousands of times, short enough that
 * an operator watching a name they just pointed here sees it within a coffee. */
const WINDOW_MS = 15 * 60 * 1000;

const lastRecorded = new Map<string, number>();

/* Test seam: the module holds process-wide state, and a spec that could not clear it would depend on
 * whichever spec ran before it. */
export function forgetHostArrivals(): void {
	lastRecorded.clear();
}

export function recordHostArrival(bucketId: string, host: string): void {
	const now = Date.now();
	const previous = lastRecorded.get(host);
	if (previous !== undefined && now - previous < WINDOW_MS) return;

	/*
	 * Claim the window before the write, not after. Claiming afterwards would let every request that
	 * arrives while the first write is in flight start a write of its own — precisely the stampede the
	 * debounce exists to prevent, and only under load, which is when it matters.
	 */
	lastRecorded.set(host, now);

	const at = new Date(now);
	void (async () => {
		try {
			const bucket = await getBucketStore().find(bucketId);
			if (!bucket) return;
			await getBucketStore().update(bucketId, {
				...(bucket.hostFirstSeenAt ? {} : { hostFirstSeenAt: at }),
				hostLastSeenAt: at
			});
		} catch {
			/*
			 * Deliberately silent. A store that cannot take this record must not turn a working sign-in
			 * into a failed one, and there is nothing an operator could do with the error that they cannot
			 * do with the absent record itself.
			 */
		}
	})();
}
