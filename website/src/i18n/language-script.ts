import { LOCALE_DEFINITIONS, translatedLocales } from '../data/seo.ts';

/*
 * The only client script on the marketing pages, and the reason it has to exist: the site is static
 * files on GitHub Pages, which cannot read Accept-Language, so the browser is the only thing that
 * knows which language its reader put first.
 *
 * It runs as the last element of <head>, before <body> is parsed, so a redirect happens before
 * anything is painted and a reveal is a CSS state rather than a swap (SC-004). What it does:
 *
 *  - decides eligibility from the FIRST browser language only — Russian or Simplified Chinese
 *    second in the list means English, untouched (FR-001, FR-002);
 *  - on an English page with a counterpart in that language, and no remembered choice of English,
 *    replaces the location with the counterpart named by the page's own hreflang link, so it can
 *    never redirect to a page that does not exist (FR-003);
 *  - otherwise stamps <html data-lang-offer> to reveal the one switcher link for that language, or
 *    data-english-only to reveal the "only in English" notice (FR-004, FR-013);
 *  - remembers a switcher click as `<chosen>@<eligible>`, so a choice made while Russian came
 *    first stops applying if Chinese later does (FR-006). Storage failures are ignored: the
 *    switch still works, it is just not remembered.
 *
 * It never navigates on a translated page — an address someone opened is the page they get
 * (FR-008) — and never for a crawler, which must index the page at the address it asked for (FR-009).
 * With scripts off, every page is exactly what its address says, and English pages are today's site.
 */

interface ScriptConfig {
	key: string;
	crawler: string;
	locales: { key: string; lang: string; eligible: readonly string[] }[];
	langToKey: Record<string, string>;
}

function languageScript(config: ScriptConfig): void {
	const html = document.documentElement;
	const pageKey = config.langToKey[html.lang] || 'en';
	const first = (
		(navigator.languages && navigator.languages[0]) ||
		navigator.language ||
		''
	).toLowerCase();

	let eligible: { key: string; lang: string } | undefined;
	for (const locale of config.locales) {
		for (const pattern of locale.eligible) {
			const matches = pattern.endsWith('*')
				? first.startsWith(pattern.slice(0, -1))
				: first === pattern;
			if (matches) eligible = locale;
		}
	}

	let choice: string | undefined;
	try {
		const stored = (localStorage.getItem(config.key) || '').split('@');
		if (eligible && stored[1] === eligible.key) choice = stored[0];
	} catch {
		// Storage blocked: no memory, and nothing else changes.
	}

	if (html.hasAttribute('data-not-found')) {
		const prefixed = /^\/(ru|zh-cn)\//.exec(location.pathname);
		html.setAttribute(
			'data-view-lang',
			prefixed?.[1]
				? prefixed[1]
				: eligible && choice !== 'en'
					? eligible.key
					: 'en'
		);
	} else if (
		eligible &&
		pageKey === 'en' &&
		!new RegExp(config.crawler, 'i').test(navigator.userAgent)
	) {
		const counterpart = document.querySelector<HTMLLinkElement>(
			`link[rel="alternate"][hreflang="${eligible.lang}"]`
		);
		// The path only: the hreflang URL is absolute on the canonical origin, and a redirect must stay
		// on whatever origin the reader is on — a preview, a staging host — and never leave the site.
		const target = counterpart ? new URL(counterpart.href).pathname : '';
		// A reader who arrived from this page's own translation chose English for it, whether or not
		// storage let that choice be remembered; sending them straight back would undo the switch.
		let fromCounterpart = false;
		try {
			fromCounterpart =
				!!document.referrer && new URL(document.referrer).pathname === target;
		} catch {
			// An unparsable referrer is no referrer.
		}
		if (counterpart && choice !== 'en' && !fromCounterpart) {
			location.replace(target + location.hash);
			return;
		}
		html.setAttribute('data-lang-offer', eligible.key);
		if (!counterpart && choice !== 'en')
			html.setAttribute('data-english-only', '');
	}

	document.addEventListener('click', (event) => {
		const target =
			event.target instanceof Element
				? event.target.closest('a[data-lang-switch]')
				: null;
		if (!(target instanceof HTMLAnchorElement)) return;
		const lang = target.getAttribute('data-lang-switch');
		if (eligible && lang !== null) {
			try {
				localStorage.setItem(config.key, `${lang}@${eligible.key}`);
			} catch {
				// As above: the switch still happens.
			}
		}
		if (location.hash) target.href = target.href.split('#')[0] + location.hash;
	});
}

/*
 * Crawlers by user agent. Not a security control — a crawler that hides is merely redirected like a
 * reader — but the honest ones must index each page at its own address.
 */
const CRAWLER = 'bot|crawl|spider|slurp|preview|yandex|baidu|lighthouse';

export function languageScriptSource(): string {
	const config: ScriptConfig = {
		key: 'foxauth.lang',
		crawler: CRAWLER,
		locales: translatedLocales().map(({ key, lang, eligible }) => ({
			key,
			lang,
			eligible
		})),
		langToKey: Object.fromEntries(
			Object.values(LOCALE_DEFINITIONS).map(({ key, lang }) => [lang, key])
		)
	};
	// Indentation and line breaks are most of the serialised function's weight, and it ships inline in
	// every page; every statement in the transpiled source ends in `;` or a brace, so joining lines is
	// safe (the build parses the result before it is used — see the check below). Whole-line comments
	// go first: the dev server's transform keeps them, and once lines are joined the first `//` would
	// comment out the rest of the function.
	const body = languageScript
		.toString()
		.replace(/^\s*\/\/.*$/gm, '')
		.replace(/\n\s*/g, '');
	const source = `(${body})(${JSON.stringify(config)});`;
	new Function(source);
	return source;
}
