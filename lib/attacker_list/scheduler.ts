import {
	ATTACKER_LIST_CHECK_MINUTE,
	ATTACKER_LIST_MAX_OFFSET_MS
} from '../consts/attacker_list.js';
import { now } from '../telemetry/clock.js';
import { flushListedCounts } from './counters.js';
import { attackerListPass } from './fetch.js';
import { effective, whenTurnedOn } from './state.js';

/*
 * A minute's tick (specs/125 research R3): it writes the sign-in counters, and once an hour — at :55, after FoxTrust's
 * :50 build is published, plus an offset of this process's own so a fleet does not ask at one instant — it checks for
 * a newer list. The first tick after start, and the first after the list is turned on, check at once. Validity is
 * three hours, so a missed hour costs nothing.
 */

const TICK_MS = 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const offsetMs = Math.floor(Math.random() * ATTACKER_LIST_MAX_OFFSET_MS);

let nextDueMs = 0;
let running = false;

whenTurnedOn(() => {
	nextDueMs = 0;
});

/* The next :55 (plus this process's offset) after `atMs`. */
export function nextCheckAfter(atMs: number, offset = offsetMs): number {
	const hourStart = Math.floor(atMs / HOUR_MS) * HOUR_MS;
	let due = hourStart + ATTACKER_LIST_CHECK_MINUTE * TICK_MS + offset;
	if (due <= atMs) due += HOUR_MS;
	return due;
}

export async function attackerListTick(): Promise<void> {
	await flushListedCounts();
	if (!effective() || running) return;
	const atMs = now().getTime();
	if (atMs < nextDueMs) return;
	running = true;
	try {
		await attackerListPass();
	} finally {
		nextDueMs = nextCheckAfter(atMs);
		running = false;
	}
}

export function startAttackerList(intervalMs: number = TICK_MS): () => void {
	const timer = setInterval(() => {
		void attackerListTick();
	}, intervalMs);
	timer.unref();
	return () => clearInterval(timer);
}

/* Test-only: a spec file starts as a process that has checked nothing yet. */
export function resetAttackerListSchedulerForTests(): void {
	nextDueMs = 0;
	running = false;
}
