import {
	ApplicationConfig,
	onSettingsApplied
} from '../configs/application.js';
import { clearLocalFailures } from './local_failures.js';
import type { Matcher } from './matcher.js';

/*
 * The attacker list this process holds and what it can say about it (specs/125, data-model "List status").
 *
 * FAILING OPEN IS THE CONTRACT HERE, the opposite of the sign-in throttle's "nothing here fails open"
 * (lib/login_throttle/throttle.ts). This is a deny list fed from outside: when it is missing, out of date, of an
 * unknown format or unverifiable, nobody is refused because of it. A list that failed closed would lock every
 * person out the moment FoxTrust — a single server — went quiet for three hours.
 */

export interface HeldList {
	readonly matcher: Matcher;
	readonly version: string;
	readonly builtAt: string;
	readonly validUntilMs: number;
	readonly entries: number;
	readonly dispute: string | null;
	readonly etag: string | null;
}

export type ProblemKind =
	| 'signature'
	| 'digest'
	| 'size'
	| 'header'
	| 'older'
	| 'expired'
	| 'format'
	| 'network'
	| 'http';

export interface Problem {
	readonly kind: ProblemKind;
	readonly at: string;
	readonly consecutive: number;
}

export type ListState =
	'off' | 'not-yet' | 'current' | 'out-of-date' | 'unknown-format';

let held: HeldList | null = null;
let lastCheckAt: string | null = null;
let lastAcceptedAt: string | null = null;
let problem: Problem | null = null;
let unknownFormat = false;
const turnedOn: (() => void)[] = [];

/* Usable only with attack reporting; validateConfiguration already refuses the one without the other. */
export function effective(): boolean {
	return (
		ApplicationConfig['attackerList.enabled'] &&
		ApplicationConfig['attackReports.enabled']
	);
}

export function heldList(): HeldList | null {
	return held;
}

/* The list a sign-in may consult at `nowMs`, or null: off, nothing accepted yet, or past its validity. */
export function listInEffect(nowMs: number): HeldList | null {
	if (!effective() || !held) return null;
	return nowMs < held.validUntilMs ? held : null;
}

export function noteCheck(atMs: number): void {
	lastCheckAt = new Date(atMs).toISOString();
}

export function acceptList(next: HeldList, atMs: number): void {
	held = next;
	lastAcceptedAt = new Date(atMs).toISOString();
	problem = null;
	unknownFormat = false;
}

/* A same-version check leaves the held list as it is and clears nothing but a stale format complaint. */
export function noteUnchanged(): void {
	unknownFormat = false;
}

export function noteUnknownFormat(atMs: number): void {
	unknownFormat = true;
	noteProblem('format', atMs);
}

export function noteProblem(kind: ProblemKind, atMs: number): void {
	problem = {
		kind,
		at: new Date(atMs).toISOString(),
		consecutive: problem?.kind === kind ? problem.consecutive + 1 : 1
	};
}

/*
 * FoxTrust writes the manifest's signature before the file, so one mismatch around :50 is normal. A signature or
 * digest problem is shown once it repeats; every other kind at once.
 */
export function shownProblem(): Problem | null {
	if (!problem) return null;
	if (
		(problem.kind === 'signature' || problem.kind === 'digest') &&
		problem.consecutive < 2
	) {
		return null;
	}
	return problem;
}

export function listState(nowMs: number): ListState {
	if (!effective()) return 'off';
	if (unknownFormat && (!held || nowMs >= held.validUntilMs)) {
		return 'unknown-format';
	}
	if (!held) return 'not-yet';
	return nowMs < held.validUntilMs ? 'current' : 'out-of-date';
}

export interface ListStatus {
	enabled: boolean;
	effective: boolean;
	state: ListState;
	held: {
		version: string;
		builtAt: string;
		validUntil: string;
		entries: number;
	} | null;
	lastCheckAt: string | null;
	lastAcceptedAt: string | null;
	lastProblem: Problem | null;
	scope: 'process';
}

export function listStatus(nowMs: number): ListStatus {
	return {
		enabled: ApplicationConfig['attackerList.enabled'],
		effective: effective(),
		state: listState(nowMs),
		held: held
			? {
					version: held.version,
					builtAt: held.builtAt,
					validUntil: new Date(held.validUntilMs).toISOString(),
					entries: held.entries
				}
			: null,
		lastCheckAt,
		lastAcceptedAt,
		lastProblem: shownProblem(),
		scope: 'process'
	};
}

/* The scheduler's hook: a pass soon after the list is turned on. */
export function whenTurnedOn(listener: () => void): void {
	turnedOn.push(listener);
}

function forget(): void {
	held = null;
	lastCheckAt = null;
	lastAcceptedAt = null;
	problem = null;
	unknownFormat = false;
	clearLocalFailures();
}

/*
 * Either switch changing drops what this process holds: off, it means nothing; on again, it is fetched afresh
 * within a minute rather than trusted from before. The test harness applies settings once per spec file, which
 * is what keeps one file's list out of the next.
 */
onSettingsApplied((appliedKeys) => {
	if (
		!appliedKeys.includes('attackerList.enabled') &&
		!appliedKeys.includes('attackReports.enabled')
	) {
		return;
	}
	forget();
	if (effective()) {
		for (const listener of turnedOn) listener();
	}
});

/* Test-only: a spec file starts with no list from the one before it. */
export function resetAttackerListForTests(): void {
	forget();
}
