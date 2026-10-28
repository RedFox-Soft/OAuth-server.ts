import { getTelemetryStateStore } from '../adapters/index.js';
import { GRANT_SHORT_NAMES } from '../consts/telemetry_fields.js';
import { now } from './clock.js';

/*
 * The day figures of the usage report, counted in this process and added to the shared state on every pass.
 *
 * Every process issues tokens but only one sends the report, so the counts have to meet in the database;
 * one write per process per quarter-hour costs nothing, one per token would. A crash loses at most the
 * counts since the last flush, which a report expressed in ranges does not notice.
 *
 * `note*` are called on the token path and in the fault-capture choke point, so they are synchronous and
 * cannot throw: counting must never slow or fail what is being counted (the argument of activity/note.ts).
 */
interface Tally {
	tokens: Map<string, number>;
	serverErrors: number;
}

let tallies = new Map<string, Tally>();

function dayOf(at: Date): string {
	return at.toISOString().slice(0, 10);
}

function tallyFor(day: string): Tally {
	let tally = tallies.get(day);
	if (!tally) {
		tally = { tokens: new Map(), serverErrors: 0 };
		tallies.set(day, tally);
	}
	return tally;
}

export function noteTokens(grantType: string): void {
	if (!Object.hasOwn(GRANT_SHORT_NAMES, grantType)) return;
	const name = GRANT_SHORT_NAMES[grantType];
	const tokens = tallyFor(dayOf(now())).tokens;
	tokens.set(name, (tokens.get(name) ?? 0) + 1);
}

export function noteServerError(): void {
	tallyFor(dayOf(now())).serverErrors += 1;
}

const KEPT_DAYS = 3;

function keptDays(at: Date): string[] {
	return Array.from({ length: KEPT_DAYS }, (_, back) =>
		dayOf(new Date(at.getTime() - back * 24 * 60 * 60 * 1000))
	);
}

/*
 * Moves this process's tallies into the shared state. They are swapped out before the first await, so
 * counting that happens during the write lands in the next flush; on failure they are added back rather
 * than lost, and the next pass tries again. Never throws.
 */
export async function flushCounts(at: Date): Promise<void> {
	const pending = tallies;
	tallies = new Map();
	const keep = keptDays(at);
	const store = getTelemetryStateStore();
	for (const [day, tally] of pending) {
		if (!keep.includes(day)) continue;
		try {
			await store.addCounts(
				day,
				{
					tokens: Object.fromEntries(tally.tokens),
					serverErrors: tally.serverErrors
				},
				keep
			);
		} catch {
			const restored = tallyFor(day);
			for (const [name, count] of tally.tokens) {
				restored.tokens.set(name, (restored.tokens.get(name) ?? 0) + count);
			}
			restored.serverErrors += tally.serverErrors;
		}
	}
}

/* Test-only: a spec file starts with no counts left over from the one before it. */
export function resetTelemetryCountsForTests(): void {
	tallies = new Map();
}
