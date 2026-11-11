import type { NetworkFacts } from '../behind_proxy/conditions.js';
import type { Address } from '../behind_proxy/net.js';
import {
	ApplicationConfig,
	onSettingsApplied
} from '../configs/application.js';
import { NETWORK_FACTS_STALE_SECONDS } from '../consts/network_facts.js';
import type { LoadedPair } from './facts.js';

/*
 * The network facts this process holds and what it can say about them (specs/129 data-model §4-§5).
 *
 * FAILING CLOSED IS THE CONTRACT HERE, the opposite of the attacker list's (lib/attacker_list/state.ts). The attacker
 * list refuses people, so missing data must refuse nobody. A network facts condition lets people in, so data that is
 * off, not loaded yet, more than 26 hours old or unreadable for an address must let nobody in through it: such facts
 * are `{ known: false }`, and every condition on them fails (research R7).
 */

export type ProblemKind =
	| 'signature'
	| 'digest'
	| 'size'
	| 'header'
	| 'older'
	| 'format'
	| 'base'
	| 'network'
	| 'http';

export interface Problem {
	readonly kind: ProblemKind;
	readonly at: string;
	readonly consecutive: number;
}

export type NetworkFactsState = 'off' | 'not-yet' | 'current' | 'stale';

const UNKNOWN: NetworkFacts = Object.freeze({ known: false });

let held: LoadedPair | null = null;
let lastCheckAt: string | null = null;
let lastAcceptedAt: string | null = null;
let problem: Problem | null = null;
let unreadableReads = 0;
const turnedOn: (() => void)[] = [];

export function networkFactsOn(): boolean {
	return ApplicationConfig['networkFacts.enabled'];
}

export function heldPair(): LoadedPair | null {
	return held;
}

export function noteCheck(atMs: number): void {
	lastCheckAt = new Date(atMs).toISOString();
}

/* One assignment: a check reads either the old pair or the new one, never a mixture or nothing (FR-005). */
export function acceptPair(next: LoadedPair, atMs: number): void {
	held = next;
	lastAcceptedAt = new Date(atMs).toISOString();
	problem = null;
}

export function noteProblem(kind: ProblemKind, atMs: number): void {
	problem = {
		kind,
		at: new Date(atMs).toISOString(),
		consecutive: problem?.kind === kind ? problem.consecutive + 1 : 1
	};
}

export function noteUnreadable(): void {
	unreadableReads += 1;
}

/*
 * FoxTrust writes a signature before the file it signs, so one mismatch around :50 is normal. A signature or digest
 * problem is shown once it repeats; every other kind at once (as lib/attacker_list/state.ts).
 */
function shownProblem(): Problem | null {
	if (!problem) return null;
	if (
		(problem.kind === 'signature' || problem.kind === 'digest') &&
		problem.consecutive < 2
	) {
		return null;
	}
	return problem;
}

function ageSeconds(pair: LoadedPair, nowMs: number): number {
	return Math.max(0, Math.floor((nowMs - Date.parse(pair.builtAt)) / 1000));
}

export function networkFactsState(nowMs: number): NetworkFactsState {
	if (!networkFactsOn()) return 'off';
	if (!held) return 'not-yet';
	return ageSeconds(held, nowMs) > NETWORK_FACTS_STALE_SECONDS
		? 'stale'
		: 'current';
}

/* What the snapshot says about `address`, or unknown whenever the pair is not current. */
export function factsAt(address: Address, nowMs: number): NetworkFacts {
	if (networkFactsState(nowMs) !== 'current' || !held) return UNKNOWN;
	return held.factsOf(address);
}

export interface NetworkFactsStatus {
	enabled: boolean;
	state: NetworkFactsState;
	held: {
		fullVersion: string;
		deltaVersion: string | null;
		builtAt: string;
		ageSeconds: number;
		ranges: number;
	} | null;
	lastCheckAt: string | null;
	lastAcceptedAt: string | null;
	lastProblem: Problem | null;
	unreadableReads: number;
	scope: 'process';
}

export function networkFactsStatus(nowMs: number): NetworkFactsStatus {
	return {
		enabled: networkFactsOn(),
		state: networkFactsState(nowMs),
		held: held
			? {
					fullVersion: held.fullVersion,
					deltaVersion: held.deltaVersion,
					builtAt: held.builtAt,
					ageSeconds: ageSeconds(held, nowMs),
					ranges: held.ranges
				}
			: null,
		lastCheckAt,
		lastAcceptedAt,
		lastProblem: shownProblem(),
		unreadableReads,
		scope: 'process'
	};
}

/* The short form every administrator sees beside conditions (specs/129 FR-009, FR-028). */
export function networkFactsSummary(nowMs: number): {
	state: NetworkFactsState;
	builtAt: string | null;
} {
	return { state: networkFactsState(nowMs), builtAt: held?.builtAt ?? null };
}

/* The scheduler's hook: a pass soon after the download is turned on. */
export function whenTurnedOn(listener: () => void): void {
	turnedOn.push(listener);
}

function forget(): void {
	held = null;
	lastCheckAt = null;
	lastAcceptedAt = null;
	problem = null;
	unreadableReads = 0;
}

/*
 * The switch changing drops what this process holds: off, it frees the memory and means nothing; on again, the data
 * is fetched afresh within a minute rather than trusted from before.
 */
onSettingsApplied((appliedKeys) => {
	if (!appliedKeys.includes('networkFacts.enabled')) return;
	forget();
	if (networkFactsOn()) {
		for (const listener of turnedOn) listener();
	}
});

/* Test-only: a spec file starts with no data from the one before it. */
export function resetNetworkFactsForTests(): void {
	forget();
}
