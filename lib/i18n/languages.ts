/*
 * The languages end-user pages and emails are written in, and the one way an outside value becomes one.
 *
 * Everything that names a language — a header, `ui_locales`, a cookie, a stored profile, a form field — goes
 * through `lookup` before it reaches markup, a header or a cookie, so only these three tags are ever emitted.
 * That is what lets every caller treat the result as trusted, and why an unsupported or malformed value is
 * simply no match rather than an error: OIDC Core §3.1.2.1 says an unsupported `ui_locales` SHOULD NOT fail
 * the request, and nothing else here has a better reason to.
 *
 * A leaf module: the client bundle imports it.
 */

export const SUPPORTED_LANGUAGES = ['en', 'ru', 'zh-Hans'] as const;

export type Language = (typeof SUPPORTED_LANGUAGES)[number];

export const NATIVE_NAMES: Record<Language, string> = {
	en: 'English',
	ru: 'Русский',
	'zh-Hans': '简体中文'
};

// `en-GB` for English keeps the day-month-year date the consent page has always shown; `en` would switch it
// to the American order for every existing English reader.
export const FORMAT_LOCALE: Record<Language, string> = {
	en: 'en-GB',
	ru: 'ru',
	'zh-Hans': 'zh-Hans'
};

export function isLanguage(value: unknown): value is Language {
	return (
		typeof value === 'string' &&
		(SUPPORTED_LANGUAGES as readonly string[]).includes(value)
	);
}

const MAX_RANGE_LENGTH = 35;

function matchOne(range: string): Language | undefined {
	if (range === '' || range === '*' || range.length > MAX_RANGE_LENGTH) {
		return undefined;
	}
	let canonical: string;
	try {
		// Throws on `en_US` and on anything that is not a tag at all, which is exactly "no match".
		[canonical] = Intl.getCanonicalLocales(range);
	} catch {
		return undefined;
	}
	const locale = new Intl.Locale(canonical);
	if (locale.language === 'zh') {
		// Compared by script, not by tag: `zh-TW` is Traditional Chinese and must never be served Simplified.
		return locale.maximize().script === 'Hans' ? 'zh-Hans' : undefined;
	}
	if (locale.language === 'en') return 'en';
	if (locale.language === 'ru') return 'ru';
	return undefined;
}

/* RFC 4647 §3.4 Lookup: the first range that matches a supported language decides. */
export function lookup(ranges: readonly string[]): Language | undefined {
	for (const range of ranges) {
		const match = matchOne(range.trim());
		if (match !== undefined) return match;
	}
	return undefined;
}
