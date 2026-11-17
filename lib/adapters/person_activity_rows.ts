import { MAX_TOOLS_PER_ROW } from '../consts/person_activity.js';
import type { PersonActivityCursor, PersonActivityRow } from './types.js';

/*
 * The one definition of how two writes of the same activity row combine, shared by the in-memory store and the
 * buffer that feeds every store, so the backends' "add, lower, raise, replace" cannot drift from what the buffer
 * means by it. MongoDB and PostgreSQL express the same rule in their own update language.
 */
export function addTo(
	existing: PersonActivityRow,
	next: PersonActivityRow
): PersonActivityRow {
	const { lookup: _kept, ...rest } = existing;
	const lookup = lookupAfter(existing, next);
	return {
		...rest,
		...(next.address === undefined
			? {}
			: { address: next.address, addressFrom: next.addressFrom }),
		...(lookup === undefined ? {} : { lookup }),
		...(next.facts === undefined ? {} : { facts: next.facts }),
		...(next.device === undefined ? {} : { device: next.device }),
		...(existing.tools === undefined && next.tools === undefined
			? {}
			: { tools: unionOfTools(existing.tools, next.tools) }),
		count: existing.count + next.count,
		firstAt: earlier(existing.firstAt, next.firstAt),
		lastAt: later(existing.lastAt, next.lastAt),
		expiresAt: later(existing.expiresAt, next.expiresAt)
	};
}

/*
 * A row's network owner and location follow its address (specs/136 research R5): a new answer replaces the kept one,
 * a write without one keeps the kept one while the address is the same, and a different address drops it, so an owner
 * never sits beside an address it was not found for and a minute whose lookups were used up erases nothing.
 */
export function lookupAfter(
	existing: PersonActivityRow,
	next: PersonActivityRow
): PersonActivityRow['lookup'] {
	if (next.address === undefined) return existing.lookup;
	if (next.lookup !== undefined) return next.lookup;
	return next.address === existing.address ? existing.lookup : undefined;
}

/*
 * An API use row's tools (specs/134 research R3): the names kept, then the new ones not kept, in their order, cut at
 * twenty. MongoDB's pipeline and PostgreSQL's statement compute the same list.
 */
export function unionOfTools(
	kept: readonly string[] | undefined,
	added: readonly string[] | undefined
): string[] {
	const tools = [...(kept ?? [])];
	for (const tool of added ?? []) {
		if (tools.length >= MAX_TOOLS_PER_ROW) break;
		if (!tools.includes(tool)) tools.push(tool);
	}
	return tools.slice(0, MAX_TOOLS_PER_ROW);
}

function earlier(a: Date, b: Date): Date {
	return a.getTime() <= b.getTime() ? a : b;
}

function later(a: Date, b: Date): Date {
	return a.getTime() >= b.getTime() ? a : b;
}

/* Newest `lastAt` first, then `_id` descending: a total order, so a page boundary never drops or repeats a row. */
export function newestFirst(
	a: PersonActivityRow,
	b: PersonActivityRow
): number {
	const byTime = b.lastAt.getTime() - a.lastAt.getTime();
	if (byTime !== 0) return byTime;
	return a._id < b._id ? 1 : a._id > b._id ? -1 : 0;
}

/* Strictly after the cursor in `newestFirst` order. */
export function isBefore(
	row: PersonActivityRow,
	cursor: PersonActivityCursor
): boolean {
	const time = row.lastAt.getTime();
	const at = cursor.lastAt.getTime();
	return time < at || (time === at && row._id < cursor.id);
}
