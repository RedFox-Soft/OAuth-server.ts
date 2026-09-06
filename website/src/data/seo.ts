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

/*
 * Bands, not targets. Above the upper bound a search engine truncates; below the lower bound the
 * slot is wasted on something that carries no query intent. Non-indexable pages are exempt.
 */
export const TITLE_BAND = { min: 15, max: 60 } as const;
export const DESCRIPTION_BAND = { min: 70, max: 160 } as const;

/*
 * Routes kept out of search results, the sitemap and every machine-readable surface. Matched as
 * prefixes against the normalised route, so a section is excluded by listing its directory.
 */
export const NON_INDEXABLE_ROUTES: readonly string[] = ['/styleguide/', '/404'];

export type SectionName =
	| 'Start here'
	| 'Product'
	| 'Compare'
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
	'Documentation',
	'Reference',
	'Project'
];

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
	return !NON_INDEXABLE_ROUTES.some((prefix) => normalised.startsWith(prefix));
}

export function sectionFor(route: string): SectionName | undefined {
	const normalised = normaliseRoute(route);
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
