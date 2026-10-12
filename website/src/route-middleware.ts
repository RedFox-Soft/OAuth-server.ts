import { defineRouteMiddleware } from '@astrojs/starlight/route-data';
import { getCollection } from 'astro:content';
import {
	LOCALE_DEFINITIONS,
	SITE_ORIGIN,
	normaliseRoute,
	stripLocale
} from './data/seo.ts';

/*
 * Starlight declares every configured language as an alternate on every docs page, whether that
 * page is translated or not, and indexes its fallback pages — the English body under translated
 * navigation — as if they were Russian or Chinese. Both would tell a search engine something false.
 *
 * So: a fallback page declares no alternates and names the English page it repeats as its canonical,
 * and any other docs page declares only the languages it actually exists in, with no alternates at
 * all when that is English alone (the Reference pages, which are generated and never translated, are
 * the standing example).
 *
 * Canonical rather than `noindex`, which the fallbacks carried until 2026-10-12: every translated
 * page links into them, so Google crawled each one, found it excluded by its own tag while naming
 * itself canonical, and reported thirty translated-looking URLs as blocked. A fallback is a duplicate
 * of the English page, and a canonical is how a duplicate says so — its links count for the page it
 * copies instead of for nothing.
 */

const LANG_TO_KEY = new Map(
	Object.values(LOCALE_DEFINITIONS).map((locale) => [locale.lang, locale.key])
);

let ids: Promise<Set<string>> | undefined;
function docIds(): Promise<Set<string>> {
	ids ??= getCollection('docs').then(
		(entries) => new Set(entries.map((entry) => entry.id))
	);
	return ids;
}

function isHreflang(entry: {
	tag: string;
	attrs?: Record<string, unknown>;
}): boolean {
	return (
		entry.tag === 'link' &&
		entry.attrs?.rel === 'alternate' &&
		'hreflang' in (entry.attrs ?? {})
	);
}

export const onRequest = defineRouteMiddleware(async (context) => {
	const route = context.locals.starlightRoute;

	if (route.isFallback) {
		const english = new URL(
			stripLocale(normaliseRoute(context.url.pathname)),
			SITE_ORIGIN
		).href;
		route.head = route.head
			.filter((entry) => !isHreflang(entry))
			.map((entry) => {
				if (entry.tag === 'link' && entry.attrs?.rel === 'canonical')
					return { ...entry, attrs: { ...entry.attrs, href: english } };
				if (entry.tag === 'meta' && entry.attrs?.property === 'og:url')
					return { ...entry, attrs: { ...entry.attrs, content: english } };
				return entry;
			});
		return;
	}

	const known = await docIds();
	const englishId = route.locale
		? route.id.slice(route.locale.length + 1)
		: route.id;
	const exists = (lang: unknown): boolean => {
		const key = typeof lang === 'string' ? LANG_TO_KEY.get(lang) : undefined;
		if (!key) return false;
		return known.has(key === 'en' ? englishId : `${key}/${englishId}`);
	};

	const translated = route.head.some(
		(entry) =>
			isHreflang(entry) &&
			entry.attrs?.hreflang !== 'en' &&
			entry.attrs?.hreflang !== 'x-default' &&
			exists(entry.attrs?.hreflang)
	);
	route.head = route.head.filter((entry) => {
		if (!isHreflang(entry)) return true;
		if (!translated) return false;
		return (
			entry.attrs?.hreflang === 'x-default' || exists(entry.attrs?.hreflang)
		);
	});
});
