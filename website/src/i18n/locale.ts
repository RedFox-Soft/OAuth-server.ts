import { getCollection } from 'astro:content';
import {
	LOCALE_DEFINITIONS,
	localeOf,
	normaliseRoute,
	stripLocale,
	translatedLocales,
	type Locale,
	type LocaleKey
} from '../data/seo.ts';
import { publishedPosts } from '../data/blog.ts';

/* `/features/` in Russian is `/ru/features/`; English is unprefixed. */
export function localizedRoute(
	englishRoute: string,
	locale: LocaleKey
): string {
	const route = normaliseRoute(englishRoute);
	return locale === 'en' ? route : `/${locale}${route}`;
}

/*
 * Rewrites a site-relative link for a page in `locale`: a target that exists in that language gets
 * the language prefix, anything else (an English-only page, an external URL, a mail link) is left as
 * it is, so a Russian page links to the Russian pricing page and to the English changelog.
 */
export async function localizedHref(
	href: string,
	locale: LocaleKey
): Promise<string> {
	if (locale === 'en' || !href.startsWith('/') || href.startsWith('//'))
		return href;
	const [path = '', hash = ''] = href.split('#');
	if (/\.[a-z]+$/.test(path)) {
		return (await translatedRoutes(locale)).has(path)
			? `/${locale}${path}${hash ? `#${hash}` : ''}`
			: href;
	}
	const route = normaliseRoute(path);
	return (await translatedRoutes(locale)).has(route) || isDocsRoute(route)
		? `/${locale}${route}${hash ? `#${hash}` : ''}`
		: href;
}

/*
 * Docs sections that are not translated still exist under the language prefix, as Starlight's
 * fallback pages — English body, translated navigation — so a link from translated docs stays in
 * the reader's language.
 */
function isDocsRoute(route: string): boolean {
	return route.startsWith('/docs/') && !route.startsWith('/docs/reference/');
}

/* The marketing pages that have a version in every published language. */
export const TRANSLATED_PAGES: readonly string[] = [
	'/',
	'/features/',
	'/pricing/',
	'/contact/',
	'/compare/',
	'/blog/'
];

const cache = new Map<LocaleKey, Promise<Set<string>>>();

/* Every English route that has a counterpart in `locale`, plus that language's feed. */
export function translatedRoutes(locale: LocaleKey): Promise<Set<string>> {
	let routes = cache.get(locale);
	if (!routes) {
		routes = collectTranslatedRoutes(locale);
		cache.set(locale, routes);
	}
	return routes;
}

async function collectTranslatedRoutes(
	locale: LocaleKey
): Promise<Set<string>> {
	const routes = new Set<string>();
	if (!translatedLocales().some((candidate) => candidate.key === locale))
		return routes;

	for (const page of TRANSLATED_PAGES) routes.add(page);
	routes.add('/blog/rss.xml');

	for (const entry of await getCollection('docs')) {
		const prefix = `${locale}/`;
		if (!entry.id.startsWith(prefix)) continue;
		routes.add(normaliseRoute(`/${entry.id.slice(prefix.length)}`));
	}
	for (const post of await publishedPosts(locale)) {
		routes.add(`/blog/${post.slug}/`);
	}
	return routes;
}

export interface Alternate {
	locale: Locale;
	href: string;
}

/*
 * The language versions of a route that actually exist, its own included. Empty for a page that
 * exists only in English, which is what tells the switcher to offer nothing and the head to declare
 * no alternates at all.
 */
export async function alternatesFor(route: string): Promise<Alternate[]> {
	const english = stripLocale(normaliseRoute(route));
	const found: Alternate[] = [];
	for (const locale of translatedLocales()) {
		if ((await translatedRoutes(locale.key)).has(english)) {
			found.push({ locale, href: localizedRoute(english, locale.key) });
		}
	}
	if (found.length === 0) return [];
	return [{ locale: LOCALE_DEFINITIONS.en, href: english }, ...found];
}

export { localeOf };
