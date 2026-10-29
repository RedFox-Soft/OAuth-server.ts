import { ApplicationConfig } from '../configs/application.js';
import { getTelemetryStateStore } from '../adapters/index.js';
import { ATTACK_DESTINATION } from '../consts/attack_report_fields.js';
import { now } from '../telemetry/clock.js';
import { sendReport } from '../telemetry/send.js';
import { slotOf } from '../telemetry/slot.js';
import { buildAttackReport, type AttackReport } from './report.js';
import { discardAll, dropHoursBefore, hourOf, takeHour } from './tally.js';

export type AttackPassOutcome =
	| 'off'
	| 'waiting'
	| 'already-handled'
	| 'discarded'
	| 'no-report'
	| 'delivered'
	| 'not-delivered';

const HOUR_MS = 60 * 60 * 1000;

/*
 * Spread over the first 25 minutes so instances do not all arrive at the top of the hour; with a five-minute
 * tick every report has left by minute 30 (FR-010), and an hour not sent by then is dropped, never sent late.
 */
const SPREAD_MINUTES = 25;
const LAST_MINUTE = 30;

/*
 * The last hour this process sent or dropped. It only moves forward, so a clock that jumps back cannot make a
 * second report for an hour already handled (FR-009).
 */
let lastHandledHour: string | null = null;

/*
 * One pass: once this instance's minute of the hour has come, report the hour that ended, then forget it.
 *
 * Each process reports what it saw. There is no claim in the datastore as the usage report has: the receiver
 * sums reports by instance and hour, and a claim would make one process's report hide another's addresses.
 *
 * Swallows everything. A report that cannot be made or delivered is not an error and is never retried (owner,
 * 2026-10-28), and a rejection from a timer would take the process with it.
 */
export async function attackReportPass(
	at: Date = now(),
	send: (report: AttackReport) => Promise<boolean> = (report) =>
		sendReport(report, ATTACK_DESTINATION),
	{ ignoreSlot = false }: { ignoreSlot?: boolean } = {}
): Promise<AttackPassOutcome> {
	try {
		if (!ApplicationConfig['attackReports.enabled']) {
			discardAll();
			return 'off';
		}
		const current = hourOf(at);
		const previous = new Date(
			new Date(current).getTime() - HOUR_MS
		).toISOString();
		if (lastHandledHour !== null && previous <= lastHandledHour) {
			return 'already-handled';
		}
		const minute = at.getUTCMinutes();
		if (!ignoreSlot && minute >= LAST_MINUTE) {
			lastHandledHour = previous;
			dropHoursBefore(current);
			return 'discarded';
		}
		const store = getTelemetryStateStore();
		const instanceId = await store.instanceId();
		if (!ignoreSlot && minute < slotOf(instanceId) % SPREAD_MINUTES) {
			return 'waiting';
		}
		lastHandledHour = previous;
		const tally = takeHour(previous);
		dropHoursBefore(current);
		const report = tally
			? buildAttackReport(previous, tally, instanceId)
			: null;
		if (!report) return 'no-report';
		const delivered = await send(report);
		// The same serialisation sendReport makes, so the console shows the bytes that left.
		await store.recordAttackSend(JSON.stringify(report), delivered ? at : null);
		return delivered ? 'delivered' : 'not-delivered';
	} catch {
		return 'no-report';
	}
}

const TICK_MS = 5 * 60 * 1000;

/* As startTelemetry: unreferenced, awaits nothing when started, logs nothing on failure. */
export function startAttackReports(intervalMs: number = TICK_MS): () => void {
	const timer = setInterval(() => {
		void attackReportPass();
	}, intervalMs);
	timer.unref();
	return () => clearInterval(timer);
}

/* Test-only: a spec file starts as a process that has reported nothing yet. */
export function resetAttackSchedulerForTests(): void {
	lastHandledHour = null;
}
