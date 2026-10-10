/*
 * Periods of activity: a UTC calendar month (`YYYY-MM`) or a UTC calendar day (`YYYY-MM-DD`).
 *
 * UTC for every bucket and every reader, because a figure that is a price has to be the same number
 * whoever reads it and from wherever. The strings are zero-padded and most-significant first, so they sort
 * lexically in time order: a range of periods is a string comparison on every backend, with nothing to
 * parse inside a query.
 */

export type Granularity = 'month' | 'day';

export const MONTH_PATTERN = /^\d{4}-(0[1-9]|1[0-2])$/;

/*
 * How long after a period ends before it may be frozen. A request served by an instance whose clock runs
 * behind could still write a mark into a period another instance considers over; until the grace has
 * passed the period reads as not final, so nobody is shown a final figure that then grows.
 */
export const CLOSE_GRACE_MS = 5 * 60 * 1000;

/* FR-021: a month's per-person marks are kept thirteen months after it ends, a day's forty days. */
const MONTH_MARK_RETENTION_MONTHS = 13;
const DAY_MARK_RETENTION_MS = 40 * 24 * 60 * 60 * 1000;

const pad = (value: number, width = 2) => String(value).padStart(width, '0');

export function monthOf(at: Date): string {
	return `${pad(at.getUTCFullYear(), 4)}-${pad(at.getUTCMonth() + 1)}`;
}

export function dayOf(at: Date): string {
	return `${monthOf(at)}-${pad(at.getUTCDate())}`;
}

export function granularityOf(period: string): Granularity {
	return period.length === 7 ? 'month' : 'day';
}

/* A month has no day part; it is read as its first day. */
function partsOf(period: string): [number, number, number] {
	const [year, month, day = 1] = period.split('-').map(Number);
	return [year, month - 1, day];
}

export function startOf(period: string): Date {
	const [year, month, day] = partsOf(period);
	return new Date(Date.UTC(year, month, day));
}

/* The first instant after the period. */
export function endOf(period: string): Date {
	const [year, month, day] = partsOf(period);
	return granularityOf(period) === 'month'
		? new Date(Date.UTC(year, month + 1, 1))
		: new Date(Date.UTC(year, month, day + 1));
}

export function isEnded(period: string, at: Date): boolean {
	return at.getTime() >= endOf(period).getTime();
}

export function isClosable(period: string, at: Date): boolean {
	return at.getTime() >= endOf(period).getTime() + CLOSE_GRACE_MS;
}

export function expiryOf(period: string): Date {
	const end = endOf(period);
	if (granularityOf(period) === 'day') {
		return new Date(end.getTime() + DAY_MARK_RETENTION_MS);
	}
	return new Date(
		Date.UTC(
			end.getUTCFullYear(),
			end.getUTCMonth() + MONTH_MARK_RETENTION_MONTHS,
			1
		)
	);
}

/* Every day of `month` up to and including the day `until` falls on, in order. */
export function daysOf(month: string, until: Date): string[] {
	const days: string[] = [];
	const last = endOf(month).getTime();
	for (
		let at = startOf(month);
		at.getTime() < last && at.getTime() <= until.getTime();
		at = new Date(at.getTime() + 24 * 60 * 60 * 1000)
	) {
		days.push(dayOf(at));
	}
	return days;
}

/* `n` months ending at `month`, newest first, `month` included. */
export function monthsBack(month: string, n: number): string[] {
	const [year, index] = partsOf(month);
	return Array.from({ length: n }, (_, back) =>
		monthOf(new Date(Date.UTC(year, index - back, 1)))
	);
}

export function previousMonth(month: string): string {
	return monthsBack(month, 2)[1];
}
