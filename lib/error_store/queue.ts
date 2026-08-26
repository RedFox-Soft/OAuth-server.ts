import { errorStore } from '../adapters/index.js';
import type { ErrorOccurrence, ErrorStoreBounds } from '../adapters/types.js';

/*
 * The write path for recorded faults: enqueue and return, flush in the background.
 *
 * Recording must not delay the response (FR-007) and a store failure must not become a second failure
 * the caller sees (FR-006), so the write cannot be awaited on the request path. A queue is also the
 * only shape that makes the loss window *stated* rather than unbounded: a process killed abruptly
 * loses at most `queueDepth` records, and a full queue counts what it could not accept instead of
 * blocking a request or dropping it silently.
 */
interface Pending {
	occurrence: ErrorOccurrence;
	bounds: ErrorStoreBounds;
}

const pending: Pending[] = [];
let flushing = false;
let dropped = 0;
let drainInstalled = false;

/*
 * Failures the queue could not accept since this process started. Non-zero means the store is missing
 * faults that really happened — which is a caveat the read surface states rather than leaving an
 * operator to assume completeness.
 */
export function droppedCount(): number {
	return dropped;
}

/* Test seam: forget the queue's state between cases. */
export function resetQueue(): void {
	pending.length = 0;
	dropped = 0;
	flushing = false;
}

async function drainOnce(): Promise<void> {
	if (flushing) {
		return;
	}
	flushing = true;
	try {
		while (pending.length > 0) {
			const next = pending.shift();
			if (!next) {
				break;
			}
			try {
				await errorStore.record(next.occurrence, next.bounds);
			} catch (error) {
				/*
				 * The store refused a write. Reported here and nowhere else: the request that produced the
				 * fault has long since been answered, so there is no caller to tell, and re-throwing would
				 * surface a storage problem as an unhandled rejection. The console is the fallback the
				 * server already used before this feature existed.
				 */
				console.error('error store could not record a fault:', error);
			}
		}
	} finally {
		flushing = false;
	}
}

/*
 * Schedules a drain without awaiting it. Deliberately not on a timer: a timer would keep the test
 * process alive and fire between unrelated specs, the same reason the memory store sweeps lazily
 * rather than on an interval.
 */
function scheduleDrain(): void {
	queueMicrotask(() => {
		void drainOnce();
	});
}

/*
 * Flushes what is queued, bounded in time.
 *
 * The bound is not caution but a requirement: a store that has stopped answering must not hold the
 * process open. A shutdown that hangs is worse than a shutdown that loses the tail, because the
 * records are lost either way and the second at least ends.
 */
export async function drainForShutdown(timeoutMs = 2000): Promise<void> {
	await Promise.race([
		drainOnce(),
		new Promise<void>((resolve) => {
			setTimeout(resolve, timeoutMs).unref?.();
		})
	]);
}

/*
 * Installs the shutdown drain once.
 *
 * Idempotent because it has to be: this codebase installs no other signal handlers, and the test suite
 * imports the app repeatedly within one process — registering per import would accumulate listeners
 * until the runtime warned about a leak. `once` is used rather than `on` so a second signal cannot
 * start a second drain.
 */
export function installShutdownDrain(): void {
	if (drainInstalled) {
		return;
	}
	drainInstalled = true;
	for (const signal of ['SIGTERM', 'SIGINT'] as const) {
		process.once(signal, () => {
			void drainForShutdown();
		});
	}
}

/*
 * Accepts one fault for recording. Never throws, never awaits a write: the caller is an error handler
 * on its way to answering a request, and nothing it does here may change that answer.
 */
export function enqueue(
	occurrence: ErrorOccurrence,
	bounds: ErrorStoreBounds,
	queueDepth: number
): void {
	const depth = Math.max(Math.trunc(queueDepth), 1);
	if (pending.length >= depth) {
		// Counted, not blocked and not silently discarded. An operator can see that recording fell
		// behind, which is the difference between an incomplete store and one that looks complete.
		dropped += 1;
		return;
	}
	pending.push({ occurrence, bounds });
	scheduleDrain();
}

/* Test seam: await the queue reaching empty, so a spec need not poll. */
export async function flushForTest(): Promise<void> {
	await drainOnce();
}
