/*
 * The person's explicit language choice, kept in the browser.
 *
 * One cookie for the whole origin, not one per bucket like the session: the choice is about the person reading,
 * not about an identity, so someone who chose English in one bucket wants English in the next one on the same
 * address. It is host-only like every end-user cookie, so a host-addressed bucket keeps its own. Set from this
 * one derivation only (wiki/concepts/cookie-path-scoping.md), and read back through `isLanguage`, so a forged
 * value is ignored rather than echoed.
 */

import { endUserCookieAttributes } from '../consts/param_list.js';
import { isLanguage, type Language } from './languages.js';

export const LANGUAGE_COOKIE = '_lang';

const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;

export function languageFromCookie(value: unknown): Language | undefined {
	return isLanguage(value) ? value : undefined;
}

export function languageCookie(language: Language) {
	return {
		...endUserCookieAttributes,
		value: language,
		path: '/',
		maxAge: ONE_YEAR_SECONDS
	};
}

/* The `_lang` value of a raw Cookie header, for the paths that hold a Request rather than a parsed jar. */
export function languageFromCookieHeader(
	header: string | null | undefined
): Language | undefined {
	if (!header) return undefined;
	for (const part of header.split(';')) {
		const at = part.indexOf('=');
		if (at > 0 && part.slice(0, at).trim() === LANGUAGE_COOKIE) {
			return languageFromCookie(part.slice(at + 1).trim());
		}
	}
	return undefined;
}
