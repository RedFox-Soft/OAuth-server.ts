import { getTelemetryStateStore } from '../adapters/index.js';
import { now } from './clock.js';
import { flushCounts } from './counters.js';
import { buildReport } from './report.js';
import { sendReport } from './send.js';
import { reportingAllowed } from './status.js';
import { minuteOfDay, slotOf } from './slot.js';

export type PassOutcome =
	| 'off'
	| 'before-slot'
	| 'already-reported'
	| 'no-report'
	| 'delivered'
	| 'not-delivered';

/*
 * One reporting pass: add this process's counts to the shared state, then, once today's slot has come and
 * no process has reported today, claim the day and send. A claimed day is never given back, so a report
 * that fails is not tried again until tomorrow, and a day missed is never sent later.
 *
 * Swallows everything. A report that cannot be made is not an error (owner, 2026-10-28), and a rejection
 * from a timer would take the process with it.
 */
export async function reportPass(
	at: Date = now(),
	send: (report: unknown) => Promise<boolean> = (report) => sendReport(report),
	{ ignoreSlot = false }: { ignoreSlot?: boolean } = {}
): Promise<PassOutcome> {
	try {
		const store = getTelemetryStateStore();
		const instanceId = await store.instanceId();
		await flushCounts(at);
		if (!reportingAllowed()) return 'off';
		if (!ignoreSlot && minuteOfDay(at) < slotOf(instanceId)) {
			return 'before-slot';
		}
		if (!(await store.claimDay(at.toISOString().slice(0, 10)))) {
			return 'already-reported';
		}
		const report = await buildReport(at, instanceId);
		if (!report) return 'no-report';
		const delivered = await send(report);
		// The same serialisation sendReport makes, so the console shows the bytes that left.
		await store.recordSend(JSON.stringify(report), delivered ? at : null);
		return delivered ? 'delivered' : 'not-delivered';
	} catch {
		return 'no-report';
	}
}

const TICK_MS = 15 * 60 * 1000;

/*
 * Runs a pass every quarter-hour and returns the way to stop it. Unreferenced, so it never holds a process
 * open, and it awaits nothing when started, so startup never waits on the network. Unlike the activity
 * closer it logs nothing on failure, by the same decision as above.
 */
export function startTelemetry(intervalMs: number = TICK_MS): () => void {
	const timer = setInterval(() => {
		void reportPass();
	}, intervalMs);
	timer.unref();
	return () => clearInterval(timer);
}
