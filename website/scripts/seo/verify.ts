import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
	DESCRIPTION_BAND,
	TITLE_BAND,
	coverageFor,
	isIndexable,
	normaliseRoute,
	sectionFor
} from '../../src/data/seo.ts';
import { flatten } from './collect.ts';
import type { PageRecord, VerificationResult } from './types.ts';

/*
 * The build's enforcement surface, and the reason this site can go without a test suite.
 *
 * Two properties matter more than the rule list. Every rule reads the collected PageRecord, so it
 * checks what actually shipped rather than what a source file intended — which is how generated
 * Reference pages are covered on the same terms as hand-written ones. And every violation is
 * collected before anything is reported: failing on the first would turn a metadata sweep into an
 * N-build chore, which is how a guardrail ends up switched off.
 */

const STRUCTURED_TYPES = new Set([
	'Organization',
	'SoftwareApplication',
	'TechArticle',
	'FAQPage',
	'BreadcrumbList'
]);

const REQUIRED_PROPS: Record<string, string[]> = {
	Organization: ['name', 'url', 'logo'],
	SoftwareApplication: [
		'name',
		'applicationCategory',
		'operatingSystem',
		'license',
		'url'
	],
	TechArticle: ['headline', 'description', 'author'],
	FAQPage: ['mainEntity'],
	BreadcrumbList: ['itemListElement']
};

export interface VerifyInput {
	dist: string;
	origin: string;
	pages: PageRecord[];
	sitemapRoutes: string[];
	imageSitemapRoutes: string[];
	llmsUrls: string[];
	/* Cards are generated, never committed, so a skipped capture has none to check. */
	cardsAvailable: boolean;
	/*
	 * The datastores that ship, as the words a page would use, from `docs-export.json` — which takes
	 * them from `lib/adapters/selectBackend.ts`. Passed in rather than imported so the rule below is
	 * a function of its input like every other one here, and so a test can hand it two backends the
	 * site does not have.
	 */
	storageBackends: string[];
}

export interface VerifyOutput {
	violations: VerificationResult[];
	skipped: string[];
}

export function verify(input: VerifyInput): VerifyOutput {
	const { pages, dist, origin } = input;
	const violations: VerificationResult[] = [];
	const skipped: string[] = [];
	const fail = (rule: string, route: string, detail: string): void => {
		violations.push({ rule, route, detail });
	};

	const indexable = pages.filter((page) => page.indexable);

	// --- title and summary -------------------------------------------------------------------
	const titles = new Map<string, string>();
	const descriptions = new Map<string, string>();

	for (const page of indexable) {
		if (page.title === '') fail('missing-title', page.route, 'no <title>');
		else if (
			page.title.length < TITLE_BAND.min ||
			page.title.length > TITLE_BAND.max
		) {
			fail(
				'title-length',
				page.route,
				`${page.title.length} chars, band ${TITLE_BAND.min}–${TITLE_BAND.max}: ${JSON.stringify(page.title)}`
			);
		}

		if (page.description === '')
			fail('missing-description', page.route, 'no meta description');
		else if (
			page.description.length < DESCRIPTION_BAND.min ||
			page.description.length > DESCRIPTION_BAND.max
		) {
			fail(
				'description-length',
				page.route,
				`${page.description.length} chars, band ${DESCRIPTION_BAND.min}–${DESCRIPTION_BAND.max}`
			);
		}

		const sameTitle = titles.get(page.title);
		if (sameTitle)
			fail('duplicate-title', page.route, `duplicates ${sameTitle}`);
		else if (page.title !== '') titles.set(page.title, page.route);

		const sameDescription = descriptions.get(page.description);
		if (sameDescription)
			fail(
				'duplicate-description',
				page.route,
				`duplicates ${sameDescription}`
			);
		else if (page.description !== '')
			descriptions.set(page.description, page.route);
	}

	// --- canonical, language, heading outline ------------------------------------------------
	for (const page of pages) {
		const expected = new URL(page.route, origin).href;
		if (page.canonical !== expected) {
			fail(
				'canonical-mismatch',
				page.route,
				`is ${page.canonical || '(none)'}, expected ${expected}`
			);
		}
		if (page.lang === '') fail('missing-lang', page.route, 'no lang on <html>');

		const h1s = page.headings.filter((h) => h.level === 1);
		if (h1s.length !== 1)
			fail(
				'heading-outline',
				page.route,
				`${h1s.length} <h1>, expected exactly 1`
			);
		let previous = 0;
		for (const heading of page.headings) {
			if (previous !== 0 && heading.level > previous + 1) {
				fail(
					'heading-outline',
					page.route,
					`h${previous} followed by h${heading.level}: ${JSON.stringify(heading.text.slice(0, 40))}`
				);
				break;
			}
			previous = heading.level;
		}
	}

	// --- indexing ------------------------------------------------------------------------------
	const sitemap = new Set(input.sitemapRoutes);
	const llms = new Set(
		input.llmsUrls.map((url) => normaliseRoute(new URL(url).pathname))
	);
	const imageSitemap = new Set(input.imageSitemapRoutes);

	for (const page of pages) {
		const shouldIndex = isIndexable(page.route);
		if (page.indexable !== shouldIndex) {
			fail(
				'noindex-leak',
				page.route,
				`page says indexable=${page.indexable} but src/data/seo.ts says ${shouldIndex}`
			);
		}
		if (!page.indexable) {
			for (const [name, set] of [
				['sitemap', sitemap],
				['image sitemap', imageSitemap],
				['llms.txt', llms]
			] as const) {
				if (set.has(page.route))
					fail(
						'noindex-leak',
						page.route,
						`non-indexable but listed in ${name}`
					);
			}
			if (
				existsSync(
					join(
						dist,
						page.route === '/' ? 'index.md' : `${page.route.slice(1, -1)}.md`
					)
				)
			) {
				fail(
					'noindex-leak',
					page.route,
					'non-indexable but has a .md alternate'
				);
			}
			continue;
		}

		if (!sitemap.has(page.route))
			fail(
				'sitemap-parity',
				page.route,
				'indexable but absent from the sitemap'
			);
		if (!llms.has(page.route) && sectionFor(page.route) !== undefined) {
			fail('sitemap-parity', page.route, 'indexable but absent from llms.txt');
		}
		if (page.lastmod === undefined) {
			fail(
				'missing-lastmod',
				page.route,
				`no git date for ${page.sourceFile ?? '(unresolved source)'}`
			);
		}
	}

	const built = new Set(pages.map((page) => page.route));
	for (const route of sitemap) {
		if (!built.has(route))
			fail(
				'sitemap-parity',
				route,
				'listed in the sitemap but not a built page'
			);
	}

	/*
	 * --- structured-data coverage ---------------------------------------------------------------
	 * The rules below check that what a page carries is well-formed and truthful. These two check
	 * that it carries anything at all, which is the half that was missing when the comparison pages
	 * shipped with no article markup and every rule passed.
	 */
	for (const page of indexable) {
		if (sectionFor(page.route) === undefined) {
			fail(
				'unclassified-page-type',
				page.route,
				'matches no section in SECTION_PREFIXES — classify it in src/data/seo.ts'
			);
		}
		const entry = coverageFor(page.route);
		if (!entry) {
			fail(
				'unclassified-page-type',
				page.route,
				'matches no entry in STRUCTURED_COVERAGE — classify it in src/data/seo.ts'
			);
			continue;
		}
		const present = new Set(page.structured.map((block) => block.type));
		for (const required of entry.requires) {
			if (!present.has(required)) {
				fail(
					'structured-coverage',
					page.route,
					`requires ${required}, which the page does not carry (${entry.reason})`
				);
			}
		}
	}

	// --- structured data ------------------------------------------------------------------------
	for (const page of pages) {
		const flat = flatten(page.text);
		for (const block of page.structured) {
			if (!STRUCTURED_TYPES.has(block.type)) {
				fail(
					'structured-unknown-type',
					page.route,
					`@type ${block.type} is outside the closed set`
				);
				continue;
			}
			for (const prop of REQUIRED_PROPS[block.type] ?? []) {
				if (block.props[prop] === undefined) {
					fail(
						'structured-missing-prop',
						page.route,
						`${block.type} is missing ${prop}`
					);
				}
			}
			for (const claim of block.assertedStrings) {
				if (!flat.includes(flatten(claim))) {
					fail(
						'structured-overclaim',
						page.route,
						`${block.type} claims ${JSON.stringify(claim.slice(0, 60))}, which the page does not visibly say`
					);
				}
			}
		}
	}

	// --- claims that must not outlive the code ---------------------------------------------------
	/*
	 * The rule that would have caught the drift this file was extended for.
	 *
	 * PostgreSQL shipped as a second datastore and the documentation pages were updated from a task
	 * list that named them. Everything else kept the old world: five comparison tables, the feature
	 * grid and the home page still said the server stores its data in MongoDB, and one comparison
	 * argued "most teams already run PostgreSQL; fewer already run MongoDB" as a reason to choose the
	 * competitor. Twenty-two rules passed, because none of them reads what a page *claims*.
	 *
	 * Two scoping decisions, both of which the first draft got wrong.
	 *
	 * It runs per *sentence*, not per page. A page-level check asks "does this page mention
	 * PostgreSQL anywhere", which any page comparing us to a PostgreSQL product answers yes to while
	 * saying we store data in MongoDB — the draft passed a deliberately reverted claim without a
	 * murmur. Comparison tables are checked at their source instead, by the schema in
	 * src/content.config.ts, where our cell can be read apart from the competitor's.
	 *
	 * And it stops at the /docs/ boundary. There, naming one datastore is usually a procedure rather
	 * than a claim — the Atlas page is about Atlas — so the rule would need an allowlist, and an
	 * allowlist is the part that rots. On the marketing surface there is no legitimate single-backend
	 * sentence left: the two Compose lines that used to name MongoDB now say "the database", which is
	 * also more accurate, since a Compose file ships for each.
	 *
	 * What it cannot see is prose naming no backend at all — "a Bun process and one database" would
	 * survive a third one untouched. That limit is why the copy which *can* be computed is computed,
	 * in src/data/storage.ts, rather than written and watched.
	 */
	const claimSurface = (route: string): boolean =>
		route === '/' || route.startsWith('/features/');

	if (input.storageBackends.length > 1) {
		for (const page of indexable.filter((p) => claimSurface(p.route))) {
			for (const sentence of page.text.split(/(?<=[.!?;])\s+/)) {
				const named = input.storageBackends.filter((backend) =>
					sentence.includes(backend)
				);
				if (named.length === 0 || named.length === input.storageBackends.length)
					continue;

				const missing = input.storageBackends.filter(
					(backend) => !named.includes(backend)
				);
				fail(
					'stale-datastore-claim',
					page.route,
					`"${sentence.trim().slice(0, 90)}" names ${named.join(', ')} but not ${missing.join(', ')}`
				);
			}
		}
	}

	// --- reachability ---------------------------------------------------------------------------
	const linkGraph = new Map(
		pages.map((page) => [page.route, page.outboundLinks])
	);
	const reachable = new Set<string>(['/']);
	let frontier = ['/'];
	for (let depth = 0; depth < 3 && frontier.length > 0; depth += 1) {
		const next: string[] = [];
		for (const route of frontier) {
			for (const target of linkGraph.get(route) ?? []) {
				if (!reachable.has(target)) {
					reachable.add(target);
					next.push(target);
				}
			}
		}
		frontier = next;
	}
	for (const page of indexable) {
		if (!reachable.has(page.route)) {
			fail('orphan-page', page.route, 'not reachable from / within 3 links');
		}
	}

	// --- preview cards and images ----------------------------------------------------------------
	if (input.cardsAvailable) {
		for (const page of indexable) {
			if (page.ogImage === '') {
				fail('missing-og-image', page.route, 'no og:image');
				continue;
			}
			const file = join(dist, new URL(page.ogImage).pathname);
			if (!existsSync(file))
				fail(
					'missing-og-image',
					page.route,
					`og:image ${page.ogImage} is not in dist/`
				);
		}
	} else {
		skipped.push(
			'missing-og-image (capture disabled: no cards were generated)'
		);
	}

	for (const page of pages) {
		/*
		 * A card shows the site name in its own chrome, so dropping the " — FoxAuth" suffix from
		 * og:title is right rather than a mismatch — Starlight does exactly that. Either form passes;
		 * an unrelated string does not.
		 */
		const bareTitle = page.title.replace(/\s+[—–|]\s+FoxAuth\s*$/, '').trim();
		if (page.ogTitle !== page.title && page.ogTitle !== bareTitle) {
			fail(
				'og-mismatch',
				page.route,
				`og:title ${JSON.stringify(page.ogTitle)} ≠ title`
			);
		}
		if (page.ogDescription !== page.description) {
			fail('og-mismatch', page.route, 'og:description ≠ meta description');
		}
		if (page.ogUrl !== page.canonical) {
			fail(
				'og-mismatch',
				page.route,
				`og:url ${page.ogUrl} ≠ canonical ${page.canonical}`
			);
		}

		for (const image of page.images) {
			if (image.alt.trim() === '') {
				fail('missing-alt', page.route, `figure image ${image.src} has no alt`);
			}
			if (image.width === undefined || image.height === undefined) {
				fail(
					'missing-dimensions',
					page.route,
					`figure image ${image.src} has no width/height`
				);
			}
		}
	}

	return { violations, skipped };
}

export function report(output: VerifyOutput): string {
	const width = Math.max(...output.violations.map((v) => v.rule.length), 0);
	const routeWidth = Math.max(
		...output.violations.map((v) => v.route.length),
		0
	);
	return output.violations
		.map(
			(v) =>
				`  ${v.rule.padEnd(width)}  ${v.route.padEnd(routeWidth)}  ${v.detail}`
		)
		.join('\n');
}
