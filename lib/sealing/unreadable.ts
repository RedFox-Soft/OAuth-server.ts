import { bindingOf, type SealTarget } from '../consts/sealed_fields.js';
import type { UnreadableSecret } from '../adapters/types.js';
import type { OpenFailure } from './seal.js';

/*
 * What this process has failed to open since it started, keyed by binding, and what has been repaired since:
 * the live half of the encryption status, beside the pass's report. Identifiers only, never a value.
 */
const LISTED = 500;

const unreadable = new Map<string, UnreadableSecret>();
const repaired = new Map<string, number>();

export function ownerOf(target: SealTarget): Record<string, string> {
	const owner: Record<string, string> = {};
	for (const [name, value] of Object.entries(target)) {
		if (name !== 'kind' && typeof value === 'string') owner[name] = value;
	}
	return owner;
}

export function entryOf(
	target: SealTarget,
	reason: OpenFailure,
	needsKid?: string
): UnreadableSecret {
	return {
		kind: target.kind,
		owner: ownerOf(target),
		reason,
		...(needsKid === undefined ? {} : { needsKid })
	};
}

export function noteUnreadable(
	target: SealTarget,
	reason: OpenFailure,
	needsKid?: string
): void {
	const binding = bindingOf(target);
	repaired.delete(binding);
	unreadable.set(binding, entryOf(target, reason, needsKid));
}

/* A value at this binding was opened or written again: it is no longer what the status lists. */
export function noteReadable(binding: string): void {
	if (unreadable.delete(binding)) repaired.set(binding, Date.now());
	else if (!repaired.has(binding)) repaired.set(binding, Date.now());
}

/* Every binding under a record, for a write that replaces all of that record's sealed leaves at once. */
export function noteReadableUnder(prefix: string): void {
	for (const binding of [...unreadable.keys()]) {
		if (binding.startsWith(prefix)) noteReadable(binding);
	}
	repaired.set(prefix, Date.now());
}

export function unreadableNow(): {
	entries: UnreadableSecret[];
	total: number;
} {
	const entries = [...unreadable.values()];
	return { entries: entries.slice(0, LISTED), total: entries.length };
}

/* Whether the value an older report listed under `binding` has been repaired in this process since `at`. */
export function repairedSince(binding: string, at: number): boolean {
	for (const [key, when] of repaired) {
		if (when >= at && (key === binding || binding.startsWith(key))) return true;
	}
	return false;
}

export const UNREADABLE_LISTED = LISTED;

/* Test-only. */
export function resetUnreadableForTests(): void {
	unreadable.clear();
	repaired.clear();
}
