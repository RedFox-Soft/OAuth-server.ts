import { defineRouteMiddleware } from '@astrojs/starlight/route-data';
import { getCollection } from 'astro:content';
import { LOCALE_DEFINITIONS } from './data/seo.ts';

/*
 * Starlight declares every configured language as an alternate on every docs page, whether that
 * page is translated or not, and indexes its fallback pages — the English body under translated
 * navigation — as if they were Russian or Chinese. Both would tell a search engine something false.
 *
 * So: a fallback page is `noindex` and declares no alternates, and any other docs page declares only
 * the languages it actually exists in, with no alternates at all when that is English alone (the
 * Reference pages, which are generated and never translated, are the standing example).
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
		route.head = route.head.filter((entry) => !isHreflang(entry));
		route.head.push({
			tag: 'meta',
			attrs: { name: 'robots', content: 'noindex' },
			content: ''
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
