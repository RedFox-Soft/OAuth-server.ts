import type { Address } from '../behind_proxy/net.js';
import {
	LOCAL_FAILURE_THRESHOLD,
	LOCAL_FAILURE_WINDOW_MS,
	LOCAL_TALLY_MAX_KEYS
} from '../consts/attacker_list.js';

/*
 * The password failures this process saw from addresses on the attacker list (specs/125 research R6): for each, the
 * times of the last few, which is all "three in the last hour" needs. A refusal is recorded too, and makes the
 * refusal stick: an address once refused stays refused while less than an hour passes between its attempts, so an
 * attacker cannot pace itself under the threshold, and one that stops for an hour gets three attempts again.
 *
 * Separate from the attack tally (lib/attack_reports/tally.ts), whose clock-hour buckets are handed to the hourly
 * report and cannot answer "the last hour". In memory and per process, like the per-origin limiter: a datastore
 * write per attacking request is the amplifier that limiter avoids. Never persisted, reported or logged.
 */

interface Tally {
	times: number[];
	refusing: boolean;
}

let failures = new Map<string, Tally>();

/* IPv4 as itself, IPv6 by its /64, the width the list names. */
function keyOf(address: Address): string {
	return address.version === 4
		? `4:${address.value.toString(16)}`
		: `6:${(address.value >> 64n).toString(16)}`;
}

function tallyOf(address: Address): Tally | null {
	const key = keyOf(address);
	let tally = failures.get(key);
	if (!tally) {
		if (failures.size >= LOCAL_TALLY_MAX_KEYS) return null;
		tally = { times: [], refusing: false };
		failures.set(key, tally);
	}
	return tally;
}

function remember(tally: Tally, atMs: number): void {
	tally.times.push(atMs);
	if (tally.times.length > LOCAL_FAILURE_THRESHOLD) tally.times.shift();
}

export function noteListedFailure(address: Address, atMs: number): void {
	const tally = tallyOf(address);
	if (tally) remember(tally, atMs);
}

export function noteListedRefusal(address: Address, atMs: number): void {
	const tally = tallyOf(address);
	if (!tally) return;
	tally.refusing = true;
	remember(tally, atMs);
}

/*
 * How many failures from `address` count against it at `atMs`: those within the window, or the whole threshold while
 * a refusal is being kept going by attempts less than the window apart.
 */
export function recentFailures(address: Address, atMs: number): number {
	const tally = failures.get(keyOf(address));
	if (!tally) return 0;
	const last = tally.times.at(-1);
	if (tally.refusing) {
		if (last !== undefined && atMs - last < LOCAL_FAILURE_WINDOW_MS) {
			return LOCAL_FAILURE_THRESHOLD;
		}
		tally.refusing = false;
	}
	return tally.times.filter((at) => atMs - at < LOCAL_FAILURE_WINDOW_MS).length;
}

/* The list went off: what was tallied against it means nothing without it. */
export function clearLocalFailures(): void {
	failures = new Map();
}
