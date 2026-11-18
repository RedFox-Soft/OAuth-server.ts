import type { ActivityBrowser, ActivitySystem } from '../adapters/types.js';
import { FORMAT_LOCALE, type Language } from '../i18n/languages.js';

/*
 * The words a sign-in is told in to the person it is about: their Recent sign-ins page (specs/135) and the email about
 * a new sign-in (specs/138). Brand names stay as they are in every language; "other" and the joining words are each
 * caller's catalog's.
 */

export const BROWSER_NAMES: Record<ActivityBrowser, string | null> = {
	chrome: 'Chrome',
	edge: 'Edge',
	firefox: 'Firefox',
	safari: 'Safari',
	opera: 'Opera',
	samsung: 'Samsung Internet',
	other: null
};

export const SYSTEM_NAMES: Record<ActivitySystem, string | null> = {
	windows: 'Windows',
	macos: 'macOS',
	ios: 'iOS',
	android: 'Android',
	linux: 'Linux',
	chromeos: 'ChromeOS',
	other: null
};

const countryNames = new Map<Language, Intl.DisplayNames>();

export function countryWords(code: string, language: Language): string | null {
	let names = countryNames.get(language);
	if (!names) {
		names = new Intl.DisplayNames([FORMAT_LOCALE[language]], {
			type: 'region'
		});
		countryNames.set(language, names);
	}
	const name = names.of(code);
	return name && name !== code ? name : null;
}
