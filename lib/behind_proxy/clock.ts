/*
 * Time windows for the "when" condition (specs/124 research R8). Imports nothing: `Intl` is a global in Bun and in
 * every browser the console supports, so the console's "Check access" reads a moment in a time zone exactly as the
 * check does.
 *
 * A window is local clock time in the zone of the app or API: 08:00–20:00 stays 08:00–20:00 on both sides of a
 * daylight-saving change. A window whose end comes before its start runs past midnight and belongs to its start day,
 * so "Fri 22:00–06:00" is Friday night into Saturday morning.
 */

export interface TimeWindow {
	/* 0 = Monday … 6 = Sunday. */
	readonly days: number[];
	/* Minutes from local midnight, in 15-minute steps; the end is not part of the window. */
	readonly start: number;
	readonly end: number;
}

export const MINUTES_PER_DAY = 1440;
export const MINUTES_PER_WEEK = 7 * MINUTES_PER_DAY;

const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

/* A formatter per zone: building one costs tens of microseconds, using one about one (feasibility Н2). */
const formatters = new Map<string, Intl.DateTimeFormat>();

function formatterFor(zone: string): Intl.DateTimeFormat {
	let formatter = formatters.get(zone);
	if (!formatter) {
		formatter = new Intl.DateTimeFormat('en-US', {
			timeZone: zone,
			weekday: 'short',
			hour: '2-digit',
			minute: '2-digit',
			hourCycle: 'h23'
		});
		formatters.set(zone, formatter);
	}
	return formatter;
}

/* The zone's canonical IANA name, or null for a name no runtime knows. */
export function canonicalTimeZone(name: string): string | null {
	if (name === '' || name.length > 64) return null;
	try {
		return new Intl.DateTimeFormat('en-US', {
			timeZone: name
		}).resolvedOptions().timeZone;
	} catch {
		return null;
	}
}

export function isTimeZone(name: string): boolean {
	return canonicalTimeZone(name) !== null;
}

/* Minutes since local Monday 00:00 of the week `at` falls in, in `zone`. */
export function minuteOfWeek(at: number, zone: string): number {
	let day = 0;
	let hour = 0;
	let minute = 0;
	for (const part of formatterFor(zone).formatToParts(at)) {
		if (part.type === 'weekday') day = WEEKDAYS.indexOf(part.value);
		else if (part.type === 'hour') hour = Number(part.value);
		else if (part.type === 'minute') minute = Number(part.value);
	}
	return day * MINUTES_PER_DAY + hour * 60 + minute;
}

export function inWindow(window: TimeWindow, minute: number): boolean {
	const day = Math.floor(minute / MINUTES_PER_DAY);
	const ofDay = minute % MINUTES_PER_DAY;
	if (window.start < window.end) {
		return (
			window.days.includes(day) && ofDay >= window.start && ofDay < window.end
		);
	}
	const previous = (day + 6) % 7;
	return (
		(window.days.includes(day) && ofDay >= window.start) ||
		(window.days.includes(previous) && ofDay < window.end)
	);
}

export function inAnyWindow(
	windows: readonly TimeWindow[],
	minute: number
): boolean {
	return windows.some((window) => inWindow(window, minute));
}

/* Which minutes of the week the windows open, one byte per minute: what deciding that windows grew compares. */
export function weekBitmap(windows: readonly TimeWindow[]): Uint8Array {
	const bitmap = new Uint8Array(MINUTES_PER_WEEK);
	for (let minute = 0; minute < MINUTES_PER_WEEK; minute++) {
		if (inAnyWindow(windows, minute)) bitmap[minute] = 1;
	}
	return bitmap;
}

export interface Opening {
	/* 0 = Monday … 6 = Sunday. */
	readonly day: number;
	/* Minutes from local midnight. */
	readonly minute: number;
	/* About how many minutes from now; a daylight-saving change in between can move it by the change. */
	readonly inMinutes: number;
}

/*
 * When the windows next open after `minute`, read off the week's own clock rather than computed as a date, so a
 * daylight-saving change never moves "Monday at 08:00". Null when no window ever opens.
 */
export function nextOpening(
	windows: readonly TimeWindow[],
	minute: number
): Opening | null {
	for (let ahead = 1; ahead <= MINUTES_PER_WEEK; ahead++) {
		const at = (minute + ahead) % MINUTES_PER_WEEK;
		const before = (at + MINUTES_PER_WEEK - 1) % MINUTES_PER_WEEK;
		if (inAnyWindow(windows, at) && !inAnyWindow(windows, before)) {
			return {
				day: Math.floor(at / MINUTES_PER_DAY),
				minute: at % MINUTES_PER_DAY,
				inMinutes: ahead
			};
		}
	}
	return null;
}

/*
 * When several time conditions apply to one path (a parent's and the path's own), the path opens only when every one
 * of them is open: the first minute after `minute` that all of them contain and the minute before does not.
 */
export function nextOpeningOfAll(
	windowSets: readonly (readonly TimeWindow[])[],
	minute: number
): Opening | null {
	const open = (at: number) =>
		windowSets.every((windows) => inAnyWindow(windows, at));
	for (let ahead = 1; ahead <= MINUTES_PER_WEEK; ahead++) {
		const at = (minute + ahead) % MINUTES_PER_WEEK;
		const before = (at + MINUTES_PER_WEEK - 1) % MINUTES_PER_WEEK;
		if (open(at) && !open(before)) {
			return {
				day: Math.floor(at / MINUTES_PER_DAY),
				minute: at % MINUTES_PER_DAY,
				inMinutes: ahead
			};
		}
	}
	return null;
}
