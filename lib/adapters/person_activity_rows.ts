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
	return {
		...existing,
		...(next.address === undefined
			? {}
			: { address: next.address, addressFrom: next.addressFrom }),
		...(next.facts === undefined ? {} : { facts: next.facts }),
		...(next.device === undefined ? {} : { device: next.device }),
		count: existing.count + next.count,
		firstAt: earlier(existing.firstAt, next.firstAt),
		lastAt: later(existing.lastAt, next.lastAt),
		expiresAt: later(existing.expiresAt, next.expiresAt)
	};
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
