/*
 * The single source for every indexing decision on this site.
 *
 * Before this file existed the styleguide was excluded from search results in two unconnected
 * places — a `noindex` prop read by Seo.astro, and a `!page.includes('/styleguide/')` string match
 * in astro.config.mjs. Nothing tied them together, so the next page to be marked noindex would have
 * gone on being advertised in the sitemap. Both consumers now read the list below, and
 * scripts/seo/verify.ts checks the built output against the same rules.
 */

export const SITE_ORIGIN = 'https://foxauth.dev';

export interface Band {
	min: number;
	max: number;
}

/*
 * Bands, not targets. Above the upper bound a search engine truncates; below the lower bound the
 * slot is wasted on something that carries no query intent. Non-indexable pages are exempt.
 */
export const TITLE_BAND: Band = { min: 15, max: 60 };
export const DESCRIPTION_BAND: Band = { min: 70, max: 160 };

/*
 * The languages the site can be built in. English is the site; the other two exist for readers
 * whose browser puts that language first, and nobody else is shown them (see
 * src/i18n/language-script.ts).
 *
 * `eligible` is matched, lower-cased, against the first entry of the browser's language list only.
 * A trailing `*` matches any subtag. Traditional Chinese (zh-TW, zh-HK, zh-MO, zh-Hant) is
 * deliberately absent: this translation is Simplified, and offering it to a Traditional reader
 * would be the wrong script, not a convenience.
 *
 * Chinese has its own bands because every Han character is one code unit to `.length` but takes two
 * Latin widths in a result snippet: 60 characters of Chinese is twice what a search engine shows.
 */
export type LocaleKey = 'en' | 'ru' | 'zh-cn';

export interface Locale {
	key: LocaleKey;
	/* <html lang>, hreflang and the feed's <language>. */
	lang: string;
	/* In its own script — the switcher names a language the way its readers write it. */
	label: string;
	ogLocale: string;
	eligible: readonly string[];
	titleBand: Band;
	descriptionBand: Band;
}

export const LOCALE_DEFINITIONS: Readonly<Record<LocaleKey, Locale>> = {
	en: {
		key: 'en',
		lang: 'en',
		label: 'English',
		ogLocale: 'en_US',
		eligible: [],
		titleBand: TITLE_BAND,
		descriptionBand: DESCRIPTION_BAND
	},
	ru: {
		key: 'ru',
		lang: 'ru',
		label: 'Русский',
		ogLocale: 'ru_RU',
		eligible: ['ru', 'ru-*'],
		titleBand: TITLE_BAND,
		descriptionBand: DESCRIPTION_BAND
	},
	'zh-cn': {
		key: 'zh-cn',
		lang: 'zh-CN',
		label: '简体中文',
		ogLocale: 'zh_CN',
		eligible: ['zh', 'zh-cn', 'zh-sg', 'zh-hans', 'zh-hans-*'],
		titleBand: { min: 8, max: 30 },
		descriptionBand: { min: 30, max: 80 }
	}
};

/*
 * The languages this build publishes. There is no per-language switch: a language is in this list or
 * it is not, and both translations reach main in one release, complete, or neither does.
 */
export const LOCALES: readonly Locale[] = [
	LOCALE_DEFINITIONS.en,
	LOCALE_DEFINITIONS.ru,
	LOCALE_DEFINITIONS['zh-cn']
];

export function translatedLocales(): Locale[] {
	return LOCALES.filter((locale) => locale.key !== 'en');
}

const PREFIXED: readonly LocaleKey[] = ['ru', 'zh-cn'];

/* The language a route is written in, read from its first path segment. */
export function localeOf(route: string): Locale {
	const first = route.split('/').filter(Boolean)[0];
	const key = PREFIXED.find((candidate) => candidate === first);
	return LOCALE_DEFINITIONS[key ?? 'en'];
}

/* `/ru/docs/` → `/docs/`; an English route is returned unchanged. */
export function stripLocale(route: string): string {
	const { key } = localeOf(route);
	if (key === 'en') return route;
	const rest = route.slice(key.length + 1);
	return rest === '' ? '/' : rest;
}

/*
 * The documentation sections that are translated. Every other /<locale>/docs/ page is a Starlight
 * fallback — the English body under translated navigation — which a reader can use but a search
 * engine must not index as if it were Russian or Chinese.
 */
export const TRANSLATED_DOCS: readonly string[] = ['/docs/get-started/'];
export const TRANSLATED_DOCS_EXACT: readonly string[] = ['/docs/'];

export function isDocsFallback(route: string): boolean {
	const normalised = normaliseRoute(route);
	if (localeOf(normalised).key === 'en') return false;
	const english = stripLocale(normalised);
	if (!english.startsWith('/docs/')) return false;
	if (TRANSLATED_DOCS_EXACT.includes(english)) return false;
	return !TRANSLATED_DOCS.some((prefix) => english.startsWith(prefix));
}

/*
 * Routes kept out of search results, the sitemap and every machine-readable surface. Matched as
 * prefixes against the normalised route with its language prefix removed, so a section is excluded
 * by listing its directory once for every language.
 */
export const NON_INDEXABLE_ROUTES: readonly string[] = ['/styleguide/', '/404'];

export type SectionName =
	| 'Start here'
	| 'Product'
	| 'Compare'
	| 'Blog'
	| 'Documentation'
	| 'Reference'
	| 'Project';

/*
 * Longest prefix wins, so /docs/reference/ resolves to Reference rather than Documentation. A route
 * matching nothing is a build failure rather than a silent drop into an "Other" bucket — a page
 * nobody classified is a page nobody will notice is missing from the index.
 */
const SECTION_PREFIXES: ReadonlyArray<readonly [string, SectionName]> = [
	['/docs/reference/', 'Reference'],
	['/docs/get-started/', 'Start here'],
	['/docs/', 'Documentation'],
	['/compare/', 'Compare'],
	['/blog/', 'Blog'],
	['/features/', 'Product'],
	['/pricing/', 'Product'],
	['/contact/', 'Product'],
	['/changelog/', 'Project'],
	['/security/', 'Project'],
	['/license/', 'Project'],
	['/', 'Start here']
];

export const SECTION_ORDER: readonly SectionName[] = [
	'Start here',
	'Product',
	'Compare',
	'Blog',
	'Documentation',
	'Reference',
	'Project'
];

export type StructuredType =
	| 'Organization'
	| 'SoftwareApplication'
	| 'TechArticle'
	| 'BlogPosting'
	| 'FAQPage'
	| 'BreadcrumbList';

/*
 * What each kind of page must describe about itself.
 *
 * The guardrail could already tell whether a structured description was well-formed and truthful; it
 * had no way to say one should exist. That is how the comparison pages shipped with no article
 * markup while twenty rules passed. This table is the missing half, and it is deliberately shaped
 * like SECTION_PREFIXES above — longest prefix wins, an unmatched route is a build failure — so a
 * contributor meets one idea twice rather than two ideas once.
 *
 * `requires: []` is a decision, which is why `reason` is mandatory: a page that needs nothing has to
 * say so, or "nobody classified this" and "this needs nothing" become indistinguishable.
 *
 * BreadcrumbList is not listed. Seo.astro adds it to every route below the top level automatically,
 * so requiring it per entry would be twenty copies of one fact.
 */
export interface CoverageEntry {
	prefix: string;
	requires: readonly StructuredType[];
	reason: string;
	/*
	 * Match this route exactly rather than as a prefix. Needed wherever a section index sits at the
	 * same path as the pages beneath it — /compare/ lists comparisons and is not itself one — and
	 * for `/`, which would otherwise be a catch-all that silently absorbed every unclassified route
	 * and made the unclassified-page-type rule unreachable.
	 */
	exact?: true;
}

export const STRUCTURED_COVERAGE: readonly CoverageEntry[] = [
	{
		prefix: '/compare/',
		exact: true,
		requires: [],
		reason:
			'An index listing the comparisons; the assessments are the pages beneath it.'
	},
	{
		prefix: '/compare/',
		requires: ['TechArticle', 'FAQPage'],
		reason:
			'A dated, sourced assessment of another product is an article, and was the page type that shipped without one.'
	},
	{
		prefix: '/blog/',
		exact: true,
		requires: [],
		reason:
			'An index listing the articles; the articles are the pages beneath it.'
	},
	{
		prefix: '/blog/',
		requires: ['BlogPosting'],
		reason:
			'A dated, attributed article about a subject — the page type this table exists to require.'
	},
	{
		prefix: '/docs/',
		requires: ['TechArticle'],
		reason:
			'Technical documentation; Starlight pages get it from StarlightHead.astro.'
	},
	{
		prefix: '/pricing/',
		requires: ['FAQPage'],
		reason:
			'The licensing and cost questions readers actually ask; no structured price, which would outlive the terms it describes.'
	},
	{
		prefix: '/features/',
		requires: [],
		reason:
			'A capability list, not an article. SoftwareApplication lives on the home page so one page owns the product identity.'
	},
	{
		prefix: '/contact/',
		requires: [],
		reason:
			'A form and two addresses; nothing to describe that the page does not already say.'
	},
	{
		prefix: '/changelog/',
		requires: [],
		reason:
			'Rendered from the repository CHANGELOG; a release list is not an article about a subject.'
	},
	{
		prefix: '/security/',
		requires: [],
		reason:
			'Rendered from the repository SECURITY policy, same reasoning as the changelog.'
	},
	{
		prefix: '/license/',
		requires: [],
		reason: 'Rendered from the repository LICENSE and NOTICE, same reasoning.'
	},
	{
		prefix: '/',
		exact: true,
		requires: ['Organization', 'SoftwareApplication'],
		reason: 'The one page that says who publishes this and what the product is.'
	}
];

/*
 * How long a claim about somebody else's product is trusted before it is reported as due for
 * re-checking. Long enough that a well-maintained page is not nagged, short enough that a claim
 * about a fast-moving product does not go a year unchecked.
 *
 * Passing this limit never fails a build: a build that fails because time passed blocks work
 * unrelated to the stale page, and the fix a hurried contributor reaches for is to delete the check.
 * It warns during the build and shows a notice on the page itself, which is the signal with teeth —
 * nobody leaves a "due for review" banner on a page they use to win comparisons.
 */
export const FRESHNESS_LIMIT_DAYS = 180;

/*
 * A built path in the one form the whole feature compares against: leading and trailing slash.
 * Astro emits most routes as `<name>/index.html` but the not-found page as a bare `404.html`, so
 * any .html suffix is stripped rather than just the index one.
 */
export function normaliseRoute(path: string): string {
	const withLeading = path.startsWith('/') ? path : `/${path}`;
	const withoutIndex = withLeading.replace(/(?:index)?\.html$/, '');
	if (withoutIndex === '/' || withoutIndex === '') return '/';
	return withoutIndex.endsWith('/') ? withoutIndex : `${withoutIndex}/`;
}

/** The social card filename for a route: /docs/get-started/ -> docs-get-started.png */
export function cardSlug(route: string): string {
	const normalised = normaliseRoute(route);
	if (normalised === '/') return 'index';
	return normalised.replace(/^\/|\/$/g, '').replace(/\//g, '-');
}

export function isIndexable(route: string): boolean {
	const normalised = normaliseRoute(route);
	if (isDocsFallback(normalised)) return false;
	const english = stripLocale(normalised);
	return !NON_INDEXABLE_ROUTES.some((prefix) => english.startsWith(prefix));
}

/** Longest matching prefix, or undefined for a route nobody classified — which is a build failure. */
export function coverageFor(route: string): CoverageEntry | undefined {
	const normalised = stripLocale(normaliseRoute(route));
	const exact = STRUCTURED_COVERAGE.find(
		(entry) => entry.exact && entry.prefix === normalised
	);
	if (exact) return exact;
	return [...STRUCTURED_COVERAGE]
		.filter((entry) => !entry.exact)
		.sort((a, b) => b.prefix.length - a.prefix.length)
		.find((entry) => normalised.startsWith(entry.prefix));
}

export function sectionFor(route: string): SectionName | undefined {
	const normalised = stripLocale(normaliseRoute(route));
	for (const [prefix, section] of SECTION_PREFIXES) {
		if (prefix === '/') continue;
		if (normalised.startsWith(prefix)) return section;
	}
	return normalised === '/' ? 'Start here' : undefined;
}

/*
 * Crawler policy. Being cited by assistants is the point of this feature, and everything the site
 * publishes is already public, so nothing here is a security control — a Disallow would only stop a
 * crawler reading the noindex it is supposed to obey.
 *
 * `source` and `verified` are required for the same reason the comparison pages carry them: these
 * tokens are third-party facts that change, and a list nobody can re-check is a list nobody will.
 */
export type CrawlerPurpose =
	'search' | 'ai-search' | 'ai-assistant' | 'ai-training';

export interface CrawlerDirective {
	agent: string;
	allow: boolean;
	purpose: CrawlerPurpose;
	source: string;
	verified: string;
}

/*
 * Every token below was read from the operator's own documentation on the date in `verified`, not
 * copied from a list. Two are not crawlers at all: Google-Extended and Applebot-Extended govern how
 * content their normal crawlers already fetched may be used, so allowing them is an affirmative
 * "yes, train on this" rather than a fetch permission. Perplexity-User is documented as generally
 * ignoring robots.txt, so its entry records intent rather than exerting control.
 */
export const CRAWLERS: readonly CrawlerDirective[] = [
	{
		agent: 'GPTBot',
		allow: true,
		purpose: 'ai-training',
		source: 'https://developers.openai.com/api/docs/bots',
		verified: '2026-09-06'
	},
	{
		agent: 'OAI-SearchBot',
		allow: true,
		purpose: 'ai-search',
		source: 'https://developers.openai.com/api/docs/bots',
		verified: '2026-09-06'
	},
	{
		agent: 'ChatGPT-User',
		allow: true,
		purpose: 'ai-assistant',
		source: 'https://developers.openai.com/api/docs/bots',
		verified: '2026-09-06'
	},
	{
		agent: 'ClaudeBot',
		allow: true,
		purpose: 'ai-training',
		source:
			'https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler',
		verified: '2026-09-06'
	},
	{
		agent: 'Claude-SearchBot',
		allow: true,
		purpose: 'ai-search',
		source:
			'https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler',
		verified: '2026-09-06'
	},
	{
		agent: 'Claude-User',
		allow: true,
		purpose: 'ai-assistant',
		source:
			'https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler',
		verified: '2026-09-06'
	},
	{
		agent: 'PerplexityBot',
		allow: true,
		purpose: 'ai-search',
		source: 'https://docs.perplexity.ai/guides/bots',
		verified: '2026-09-06'
	},
	{
		agent: 'Perplexity-User',
		allow: true,
		purpose: 'ai-assistant',
		source: 'https://docs.perplexity.ai/guides/bots',
		verified: '2026-09-06'
	},
	{
		agent: 'Google-Extended',
		allow: true,
		purpose: 'ai-training',
		source:
			'https://developers.google.com/search/docs/crawling-indexing/google-common-crawlers',
		verified: '2026-09-06'
	},
	{
		agent: 'Applebot-Extended',
		allow: true,
		purpose: 'ai-training',
		source: 'https://support.apple.com/en-us/119829',
		verified: '2026-09-06'
	}
];
