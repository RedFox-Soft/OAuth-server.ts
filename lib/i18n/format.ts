/*
 * Dates, lists and counts in the page's language, always with an explicit locale and time zone.
 *
 * Bun's default locale is `en-US` whatever the machine says (oven-sh/bun#8480), so a formatter built without
 * one would quietly print American English on every page. Everything is formatted here, on the server, and
 * shipped as text: the browser's ICU can disagree with Bun's, and a hydrated page that formats again would
 * rewrite its own text on load.
 */

import { FORMAT_LOCALE, type Language } from './languages.js';

function cached<T>(
	build: (language: Language) => T
): (language: Language) => T {
	const instances = new Map<Language, T>();
	return (language) => {
		let instance = instances.get(language);
		if (instance === undefined) {
			instance = build(language);
			instances.set(language, instance);
		}
		return instance;
	};
}

const dateFormat = cached(
	(language) =>
		new Intl.DateTimeFormat(FORMAT_LOCALE[language], {
			day: 'numeric',
			month: 'long',
			year: 'numeric',
			timeZone: 'UTC'
		})
);

const dayMonthFormat = cached(
	(language) =>
		new Intl.DateTimeFormat(FORMAT_LOCALE[language], {
			day: 'numeric',
			month: 'long',
			timeZone: 'UTC'
		})
);

const dateTimeFormat = cached(
	(language) =>
		new Intl.DateTimeFormat(FORMAT_LOCALE[language], {
			dateStyle: 'medium',
			timeStyle: 'short',
			timeZone: 'UTC'
		})
);

const relativeFormat = cached(
	(language) =>
		new Intl.RelativeTimeFormat(FORMAT_LOCALE[language], { numeric: 'always' })
);

const listFormat = cached(
	(language) =>
		new Intl.ListFormat(FORMAT_LOCALE[language], { type: 'conjunction' })
);

const numberFormat = cached(
	(language) => new Intl.NumberFormat(FORMAT_LOCALE[language])
);

// The year is left out when it is the current one: "until 3 March" reads as a date, "until 3 March 2026" as a
// deadline.
export function formatDate(
	language: Language,
	ms: number,
	now = Date.now()
): string {
	const sameYear =
		new Date(ms).getUTCFullYear() === new Date(now).getUTCFullYear();
	return (sameYear ? dayMonthFormat : dateFormat)(language).format(ms);
}

export function formatDateTime(language: Language, ms: number): string {
	return dateTimeFormat(language).format(ms);
}

export function formatMinutesAgo(language: Language, minutes: number): string {
	return relativeFormat(language).format(-minutes, 'minute');
}

export function formatList(
	language: Language,
	items: readonly string[]
): string {
	return listFormat(language).format(items);
}

export function formatNumber(language: Language, value: number): string {
	return numberFormat(language).format(value);
}

const zonedFormats = new Map<string, Intl.DateTimeFormat>();

/*
 * A moment in an app's own time zone (specs/124): a page that says when an app opens again must say "now" in the
 * same clock, not in UTC. Falls back to UTC for a zone no runtime knows, which the admin routes never store.
 */
export function formatDateTimeIn(
	language: Language,
	ms: number,
	zone: string | null
): string {
	if (!zone) return formatDateTime(language, ms);
	const key = `${language}|${zone}`;
	let format = zonedFormats.get(key);
	if (!format) {
		try {
			format = new Intl.DateTimeFormat(FORMAT_LOCALE[language], {
				dateStyle: 'medium',
				timeStyle: 'short',
				timeZone: zone
			});
		} catch {
			return formatDateTime(language, ms);
		}
		zonedFormats.set(key, format);
	}
	return format.format(ms);
}

const weekdayFormat = cached(
	(language) =>
		new Intl.DateTimeFormat(FORMAT_LOCALE[language], {
			weekday: 'long',
			hour: '2-digit',
			minute: '2-digit',
			hourCycle: 'h23',
			timeZone: 'UTC'
		})
);

/* A day of the week (0 = Monday) and a minute of that day, as "Monday 08:00" reads in the page's language. */
export function formatWeekdayTime(
	language: Language,
	day: number,
	minute: number
): string {
	/* 2024-01-01 was a Monday: a fixed week whose days and clock carry no zone or season. */
	const ms = Date.UTC(2024, 0, 1 + day, Math.floor(minute / 60), minute % 60);
	return weekdayFormat(language).format(ms);
}

/* "in 2 hours", "in 45 minutes": how far ahead something is, rounded to what a person plans by. */
export function formatIn(language: Language, minutes: number): string {
	if (minutes < 120) return relativeFormat(language).format(minutes, 'minute');
	if (minutes < 48 * 60) {
		return relativeFormat(language).format(Math.round(minutes / 60), 'hour');
	}
	return relativeFormat(language).format(Math.round(minutes / 1440), 'day');
}
