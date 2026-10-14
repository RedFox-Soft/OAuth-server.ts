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
