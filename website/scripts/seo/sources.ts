import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { localeOf, stripLocale, type LocaleKey } from '../../src/data/seo.ts';

/*
 * Which repository files a built route came from.
 *
 * Needed for lastmod: a page's date is the newest commit across its own source and, for the
 * generated Reference pages, the server tables the docs export reads. A Reference page whose shell
 * has not been touched in months is still out of date the moment the catalogue behind it changes,
 * and a date that ignored that would be worse than none.
 */

// Not import.meta.dir: this module is also loaded from astro.config.mjs through Vite's module
// runner, which does not define it.
const SITE = resolve(fileURLToPath(new URL('.', import.meta.url)), '../..');
const ROOT = resolve(SITE, '..');

export interface RouteSources {
	sourceFile?: string;
	dataSources: string[];
}

/*
 * Repository files a route renders but does not live in. The Reference pages read
 * website/generated/docs-export.json, which scripts/docs_export.ts builds from the server's own
 * tables; the three root documents are rendered from the repository's Markdown at build time. A
 * page is out of date the moment its inputs change, so both feed lastmod — listed per route rather
 * than as one blanket set, so a settings change does not redate the MCP tools page.
 */
const ROUTE_DATA: Record<string, string[]> = {
	'/docs/reference/settings/': [
		'lib/admin/settings/catalog.ts',
		'lib/configs/application.ts'
	],
	'/docs/reference/endpoints/': ['lib/consts/route_classification.ts'],
	'/docs/reference/admin-api/': ['lib/consts/route_classification.ts'],
	'/docs/reference/mcp-tools/': ['lib/mcp/catalogue.ts'],
	'/docs/reference/addon-seams/': ['lib/addon/seams.ts'],
	'/docs/reference/environment/': ['lib/configs/env.ts'],
	'/changelog/': ['CHANGELOG.md'],
	'/security/': ['SECURITY.md'],
	'/license/': ['LICENSE', 'NOTICE']
};

/** Candidate source files for a route, most specific first. */
function candidates(route: string): string[] {
	const trimmed = route === '/' ? '' : route.replace(/^\/|\/$/g, '');
	const asPage = trimmed === '' ? 'index' : trimmed;
	return [
		`src/pages/${asPage}.astro`,
		`src/pages/${asPage}/index.astro`,
		`src/content/docs/${asPage}.mdx`,
		`src/content/docs/${asPage}/index.mdx`,
		`src/content/docs/${asPage}.md`,
		// /compare/auth0/ and /blog/<slug>/ are rendered by their [slug].astro from this collection
		// entry — the route's first segment is also the collection directory, so one candidate
		// covers both. Without it an article falls through to the template below and reports the
		// template's commit date as its own.
		`src/content/${asPage}.mdx`
	];
}

/*
 * A translated marketing page's route file is a few lines that render the shared view; its words
 * are in the page's message module. Without the module here, a re-translation would leave the
 * page's date at whenever the route file was created. Keyed by the English route, because the
 * module directory is named after the page, not the address.
 */
const MESSAGE_GROUPS: Record<string, string[]> = {
	'/': ['home'],
	'/features/': ['features'],
	'/pricing/': ['pricing'],
	'/contact/': ['contact'],
	'/compare/': ['compare', 'compareCards'],
	'/blog/': ['blog']
};

/*
 * Where a translated route's own file can be, most specific first. Thin route files and translated
 * docs sit under a locale directory at the top of their tree (`src/pages/ru/…`,
 * `src/content/docs/ru/docs/…`), so the prefixed route maps onto them as it is. A blog translation
 * sits under the locale *inside* its collection (`src/content/blog/ru/<slug>.mdx`), because the
 * collection directory is the route's first segment and has to stay one directory.
 */
function translatedCandidates(locale: LocaleKey, english: string): string[] {
	const rest = english === '/' ? '' : english.replace(/^\/|\/$/g, '');
	const asPage = rest === '' ? 'index' : rest;
	const found = [
		`src/pages/${locale}/${asPage}.astro`,
		`src/pages/${locale}/${asPage}/index.astro`,
		`src/content/docs/${locale}/${asPage}.mdx`,
		`src/content/docs/${locale}/${asPage}/index.mdx`,
		`src/content/docs/${locale}/${asPage}.md`
	];
	const [collection, ...entry] = rest.split('/');
	if (collection && entry.length > 0) {
		found.push(`src/content/${collection}/${locale}/${entry.join('/')}.mdx`);
	}
	return found;
}

function firstExisting(candidateFiles: string[]): string | undefined {
	return candidateFiles.find((rel) => existsSync(resolve(SITE, rel)));
}

export function sourcesFor(route: string): RouteSources {
	const locale = localeOf(route).key;
	const english = stripLocale(route);
	const dataSources = (ROUTE_DATA[english] ?? []).filter((rel) =>
		existsSync(resolve(ROOT, rel))
	);

	/*
	 * A marketing page's words live in its message module, not in the thin route file, so an edit to
	 * the English text alone has to move the English page's date too.
	 */
	for (const group of MESSAGE_GROUPS[english] ?? []) {
		const rel = `website/src/i18n/messages/${group}/en.ts`;
		if (locale === 'en' && existsSync(resolve(ROOT, rel)))
			dataSources.push(rel);
	}

	if (locale !== 'en') {
		for (const group of MESSAGE_GROUPS[english] ?? []) {
			const rel = `website/src/i18n/messages/${group}/${locale}.ts`;
			if (existsSync(resolve(ROOT, rel))) dataSources.push(rel);
		}
		const own = firstExisting(translatedCandidates(locale, english));
		if (own) return { sourceFile: `website/${own}`, dataSources };
	}

	/*
	 * An English route, or a translated one with no file of its own: a documentation fallback, or a
	 * page rendered from an English collection entry, whose words — and so whose date — are the
	 * English page's.
	 */
	const shared = firstExisting(candidates(english));
	if (shared) return { sourceFile: `website/${shared}`, dataSources };

	// A dynamic route: fall back to the page template that produced it.
	const dynamic = english.match(/^\/([^/]+)\//);
	if (dynamic) {
		const templates = [`src/pages/${dynamic[1]}/[slug].astro`];
		if (locale !== 'en')
			templates.unshift(`src/pages/${locale}/${dynamic[1]}/[slug].astro`);
		const template = firstExisting(templates);
		if (template) return { sourceFile: `website/${template}`, dataSources };
	}

	return { sourceFile: undefined, dataSources };
}
