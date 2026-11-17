import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { getPersonActivityStore, getUserStore } from '../adapters/index.js';
import type { PersonActivityRow } from '../adapters/types.js';
import {
	OVERFLOW_ACCOUNT,
	PERSON_ACTIVITY_FLUSH_MS,
	PERSON_ACTIVITY_USE_FLUSH_MS
} from '../consts/person_activity.js';
import { takeAll, takeUse } from './buffer.js';
import { withLookups } from '../address_lookup/lookups.js';

/*
 * Writing what this process noted (specs/133 research R11, R12). Once a minute, everything held goes to the store in
 * sorted chunks; a chunk that fails is lost and counted, never put back, because a write adds and a retried one
 * would count twice. An undercount is the honest failure here.
 */

let flushing: Promise<void> = Promise.resolve();

/*
 * Rows of people who no longer exist are dropped before the write (S6): another process may have deleted a person
 * while this one still held their notes, and an upsert would bring their address back for 90 days. One read per
 * project in the batch, by the ids it holds.
 */
async function withoutTheDeleted(
	rows: readonly PersonActivityRow[]
): Promise<PersonActivityRow[]> {
	const byProject = new Map<string, Set<string>>();
	for (const row of rows) {
		if (row.bucketId === ADMIN_BUCKET_ID) continue;
		if (row.accountId === OVERFLOW_ACCOUNT) continue;
		let ids = byProject.get(row.bucketId);
		if (!ids) {
			ids = new Set();
			byProject.set(row.bucketId, ids);
		}
		ids.add(row.accountId);
	}
	const existing = new Set<string>();
	for (const [bucketId, ids] of byProject) {
		try {
			const found = await getUserStore(bucketId).findMany([...ids]);
			for (const user of found) existing.add(`${bucketId}\u0000${user._id}`);
		} catch (error) {
			// A project that cannot be read keeps nothing this minute: better lost than resurrected.
			console.error('activity not recorded: people could not be read', {
				bucketId,
				error
			});
		}
	}
	return rows.filter(
		(row) =>
			row.bucketId !== ADMIN_BUCKET_ID &&
			(row.accountId === OVERFLOW_ACCOUNT ||
				existing.has(`${row.bucketId}\u0000${row.accountId}`))
	);
}

async function flushOnce(take: () => PersonActivityRow[]): Promise<void> {
	const taken = take();
	if (taken.length === 0) return;
	const kept = await withoutTheDeleted(taken);
	if (kept.length === 0) return;
	/*
	 * The owner and location of each address, before the write (specs/136 research R4): the one place a person's
	 * address leaves this server, here because no request waits on a flush (SI-4). Bounded at a few seconds, and a
	 * row without an answer is written without one.
	 */
	const rows = await withLookups(kept);
	try {
		const { failed } = await getPersonActivityStore().write(rows);
		if (failed > 0) {
			/*
			 * The projects only, never an account or an address: a log line naming who did what is the record this
			 * area keeps out of every other surface (S16).
			 */
			console.error('activity partly not recorded', {
				rows: failed,
				projects: [...new Set(rows.map((row) => row.bucketId))].length
			});
		}
	} catch (error) {
		console.error('activity not recorded', { rows: rows.length, error });
	}
}

/* One write at a time: a flush that runs long is followed, never overlapped, by the next. */
function flushQueued(take: () => PersonActivityRow[]): Promise<void> {
	const run = () => flushOnce(take);
	flushing = flushing.then(run, run);
	return flushing;
}

/* Both buffers, now: what tests ask for and what a stop drains. */
export function flushPersonActivityNow(): Promise<void> {
	void flushQueued(takeAll);
	return flushQueued(takeUse);
}

let timer: ReturnType<typeof setInterval> | null = null;
let useTimer: ReturnType<typeof setInterval> | null = null;
let drainInstalled = false;

/*
 * The flush on SIGTERM and SIGINT, bounded at two seconds like the error store's and Sentry's drains: a stop that
 * waits on a slow database is worse than a minute's activity lost, which the site states.
 */
function installShutdownDrain(): void {
	if (drainInstalled) return;
	drainInstalled = true;
	for (const signal of ['SIGTERM', 'SIGINT'] as const) {
		process.once(signal, () => {
			void Promise.race([
				flushPersonActivityNow(),
				new Promise<void>((resolve) => {
					setTimeout(resolve, 2000).unref();
				})
			]);
		});
	}
}

/*
 * Started once with the server. Unreferenced, so a script that imports the app still exits when its work is done.
 * Under `bun test` the timer runs too, harmlessly: a spec asks for `flushPersonActivityNow()` when it needs the
 * rows, and the test bootstrap empties the buffer between files.
 */
export function startPersonActivity(): void {
	if (timer) return;
	timer = setInterval(() => {
		void flushQueued(takeAll);
	}, PERSON_ACTIVITY_FLUSH_MS);
	timer.unref();
	/* What people used, every five minutes (specs/134 research R2). */
	useTimer = setInterval(() => {
		void flushQueued(takeUse);
	}, PERSON_ACTIVITY_USE_FLUSH_MS);
	useTimer.unref();
	installShutdownDrain();
}
