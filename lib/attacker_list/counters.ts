import crypto from 'crypto';

import { checkedAdapter } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { now } from '../telemetry/clock.js';
import { PasswordGuessingTallyPayload } from './types.js';

/*
 * A project's figures for its Sign-in tab (specs/125 research R11): password sign-ins from listed addresses, those
 * among them with the right password, and refusals, per UTC day.
 *
 * Counted in memory on the request path — synchronous, never awaited, never throwing — and written once a minute as
 * this process's absolute totals to a record of its own, so a flush is one upsert per changed project and day and
 * no two processes ever race on a counter. A project's figure is the sum of its records over the last 7 days.
 */

export type ListOutcome = 'attempt' | 'rightPassword' | 'refused';

interface Totals {
	attempts: number;
	rightPassword: number;
	refused: number;
}

export interface ProjectCounts {
	listedAttempts: number;
	listedRightPassword: number;
	refused: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const KEEP_SECONDS = 8 * 24 * 60 * 60;
export const COUNT_DAYS = 7;

/* Names this process's records; a restarted process writes new ones and the old totals stay summed. */
const processId = crypto.randomUUID();

const totals = new Map<string, Totals>();
const dirty = new Set<string>();

function tallies() {
	return checkedAdapter('PasswordGuessingTally', PasswordGuessingTallyPayload);
}

const dayOf = (at: Date) => at.toISOString().slice(0, 10);

export function noteListed(bucketId: string, outcome: ListOutcome): void {
	try {
		const key = `${bucketId}:${dayOf(now())}`;
		let entry = totals.get(key);
		if (!entry) {
			entry = { attempts: 0, rightPassword: 0, refused: 0 };
			totals.set(key, entry);
		}
		if (outcome === 'attempt') entry.attempts += 1;
		else if (outcome === 'rightPassword') entry.rightPassword += 1;
		else {
			entry.attempts += 1;
			entry.refused += 1;
		}
		dirty.add(key);
	} catch {
		// Counting is never a reason for a sign-in to fail.
	}
}

/* Writes every changed total; the in-memory totals of past days are dropped once written. */
export async function flushListedCounts(): Promise<void> {
	const today = dayOf(now());
	for (const key of [...dirty]) {
		const entry = totals.get(key);
		dirty.delete(key);
		if (!entry) continue;
		const separator = key.lastIndexOf(':');
		const bucketId = key.slice(0, separator);
		const day = key.slice(separator + 1);
		try {
			await tallies().upsert(
				`${key}:${processId}`,
				{ bucketId, day, ...entry, exp: epochTime() + KEEP_SECONDS },
				KEEP_SECONDS
			);
		} catch {
			// The next flush writes the same absolute totals again.
			dirty.add(key);
			continue;
		}
		if (day < today) totals.delete(key);
	}
}

/* The last 7 days of a project, all processes; this process's unwritten counts are written first. */
export async function countsFor(bucketId: string): Promise<ProjectCounts> {
	await flushListedCounts();
	const today = now().getTime();
	const days = new Set(
		Array.from({ length: COUNT_DAYS }, (_, i) =>
			dayOf(new Date(today - i * DAY_MS))
		)
	);
	const sum: ProjectCounts = {
		listedAttempts: 0,
		listedRightPassword: 0,
		refused: 0
	};
	for (const record of await tallies().findByIndexed('bucketId', bucketId)) {
		if (!days.has(record.day) || record.exp <= epochTime()) continue;
		sum.listedAttempts += record.attempts;
		sum.listedRightPassword += record.rightPassword;
		sum.refused += record.refused;
	}
	return sum;
}

/* Test-only: a spec file starts with nothing counted by the one before it. */
export function resetListedCountsForTests(): void {
	totals.clear();
	dirty.clear();
}
