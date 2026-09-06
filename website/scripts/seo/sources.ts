import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
		// /compare/auth0/ is rendered by src/pages/compare/[slug].astro from this collection entry.
		`src/content/${asPage}.mdx`
	];
}

export function sourcesFor(route: string): RouteSources {
	const dataSources = (ROUTE_DATA[route] ?? []).filter((rel) =>
		existsSync(resolve(ROOT, rel))
	);

	for (const rel of candidates(route)) {
		if (existsSync(resolve(SITE, rel))) {
			return { sourceFile: `website/${rel}`, dataSources };
		}
	}

	// A dynamic route: fall back to the page template that produced it.
	const dynamic = route.match(/^\/([^/]+)\//);
	if (dynamic) {
		const template = `src/pages/${dynamic[1]}/[slug].astro`;
		if (existsSync(resolve(SITE, template))) {
			return { sourceFile: `website/${template}`, dataSources };
		}
	}

	return { sourceFile: undefined, dataSources };
}
