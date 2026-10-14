/*
 * Which language a page is shown in, from the signals that page has.
 *
 * Each signal becomes an ordered list of language ranges, and the caller passes the lists in the order the
 * product decided (specs/097): the person's explicit choice, the application's `ui_locales`, the account's
 * stored locale, the browser's `Accept-Language`, then English. One Lookup over the concatenation picks the
 * page language; the first non-English match over the same list is the `alternative` the switcher offers, so a
 * person whose stored `en` hides their Russian browser can still get back to Russian.
 *
 * Every parser is bounded: these values come from the request, and a header of a thousand ranges must not
 * cost a thousand canonicalisations.
 */

import { lookup, type Language } from './languages.js';

const MAX_SIGNAL_LENGTH = 1024;
const MAX_RANGES = 32;

export function uiLocalesRanges(value: unknown): string[] {
	if (typeof value !== 'string') return [];
	return value
		.slice(0, MAX_SIGNAL_LENGTH)
		.split(/\s+/)
		.filter(Boolean)
		.slice(0, MAX_RANGES);
}

const ACCEPT_CACHE_LIMIT = 256;
const acceptCache = new Map<string, string[]>();

function parseAcceptLanguage(header: string): string[] {
	const entries: { range: string; q: number; index: number }[] = [];
	const parts = header.slice(0, MAX_SIGNAL_LENGTH).split(',');
	for (const [index, part] of parts.slice(0, MAX_RANGES).entries()) {
		const [rawRange, ...params] = part.split(';');
		const range = rawRange.trim();
		if (range === '') continue;
		let q = 1;
		for (const param of params) {
			const at = param.indexOf('=');
			if (at < 0 || param.slice(0, at).trim().toLowerCase() !== 'q') continue;
			const value = param.slice(at + 1).trim();
			// RFC 9110 §12.4.2 restricts q to 0..1 with three decimals; anything else is treated as the default
			// rather than as a reason to discard the whole header.
			if (/^[01](\.\d{0,3})?$/.test(value)) {
				q = Number(value);
			}
		}
		if (q > 0) entries.push({ range, q, index });
	}
	// RFC 9110 §12.5.4: order among equal weights "cannot be relied upon", so the sent order breaks ties.
	entries.sort((a, b) => b.q - a.q || a.index - b.index);
	return entries.map((entry) => entry.range);
}

export function acceptLanguageRanges(
	header: string | null | undefined
): string[] {
	if (!header) return [];
	const cached = acceptCache.get(header);
	if (cached) return cached;
	const ranges = parseAcceptLanguage(header);
	if (acceptCache.size >= ACCEPT_CACHE_LIMIT) acceptCache.clear();
	acceptCache.set(header, ranges);
	return ranges;
}

export interface LocaleHolder {
	profile?: { locale?: string };
	claims?: Record<string, unknown>;
}

/*
 * `profile.locale` is what administrators and SCIM write; an upstream provider's `locale` lands in `claims`
 * (lib/federation/consts.ts COPIED_CLAIMS), so a federated account with no profile locale still has a signal.
 */
export function storedLocaleRanges(user: LocaleHolder | undefined): string[] {
	const stored = user?.profile?.locale ?? user?.claims?.locale;
	return typeof stored === 'string' ? [stored] : [];
}

export function singleRange(value: Language | undefined): string[] {
	return value === undefined ? [] : [value];
}

export interface ResolvedLanguage {
	language: Language;
	alternative?: Exclude<Language, 'en'>;
}

export function resolveLanguage(
	signals: readonly (readonly string[])[]
): ResolvedLanguage {
	const ranges = signals.flat();
	const language = lookup(ranges) ?? 'en';
	let alternative: Exclude<Language, 'en'> | undefined;
	for (const range of ranges) {
		const match = lookup([range]);
		if (match !== undefined && match !== 'en') {
			alternative = match;
			break;
		}
	}
	return alternative === undefined ? { language } : { language, alternative };
}

/*
 * The language of an email to `user` (specs/097): the account's stored locale, else the language of the page
 * the person was on when they asked for it, else English. An email can be opened anywhere, so the account's
 * own setting outranks the page that happened to trigger it.
 */
export function emailLanguage(
	user: LocaleHolder | undefined,
	pageLanguage?: Language
): Language {
	return lookup(storedLocaleRanges(user)) ?? pageLanguage ?? 'en';
}
