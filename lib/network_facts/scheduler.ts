import {
	NETWORK_FACTS_MAX_OFFSET_MS,
	NETWORK_FACTS_TICK_MS
} from '../consts/network_facts.js';
import { now } from '../telemetry/clock.js';
import { networkFactsPass, type PassOptions } from './fetch.js';
import { networkFactsOn, whenTurnedOn } from './state.js';

/*
 * A look at FoxTrust's manifest every 5 minutes (specs/129 research R4), plus an offset of this process's own so a
 * fleet does not ask at one instant. FoxTrust publishes an update at :50 each hour, so the newest one is in use within
 * 10 minutes (SC-002); an unchanged manifest costs one conditional request. The first tick after start, and the first
 * after the download is turned on, look at once. A look never overlaps the one before it.
 */

const CHECK_MS = 30 * 1000;
const offsetMs = Math.floor(Math.random() * NETWORK_FACTS_MAX_OFFSET_MS);

let nextDueMs = 0;
let running = false;

whenTurnedOn(() => {
	nextDueMs = 0;
});

/* `options` is the pass's test seam (lib/network_facts/fetch.ts); the server never passes it. */
export async function networkFactsTick(
	offset: number = offsetMs,
	options: PassOptions = {}
): Promise<void> {
	if (!networkFactsOn() || running) return;
	const atMs = now().getTime();
	if (atMs < nextDueMs) return;
	running = true;
	try {
		await networkFactsPass(options);
	} finally {
		nextDueMs = atMs + NETWORK_FACTS_TICK_MS + offset;
		running = false;
	}
}

/* A short timer that only acts when a look is due, so turning the download on is felt within half a minute. */
export function startNetworkFacts(intervalMs: number = CHECK_MS): () => void {
	const timer = setInterval(() => {
		void networkFactsTick();
	}, intervalMs);
	timer.unref();
	return () => clearInterval(timer);
}

/* Test-only: a spec file starts as a process that has looked at nothing yet. */
export function resetNetworkFactsSchedulerForTests(): void {
	nextDueMs = 0;
	running = false;
}
