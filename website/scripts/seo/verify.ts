import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
	coverageFor,
	isIndexable,
	localeOf,
	normaliseRoute,
	sectionFor,
	stripLocale
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
	'BlogPosting',
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
	/*
	 * datePublished is required where TechArticle does not require a date, because an undated
	 * article is the thing a reader cannot judge and a search engine discounts.
	 */
	BlogPosting: ['headline', 'description', 'author', 'datePublished'],
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
		/*
		 * Per language: a Han character is one code unit but two Latin widths in a result snippet,
		 * so the English band would let a Chinese title run to twice what a search engine shows.
		 */
		const { titleBand, descriptionBand } = localeOf(page.route);
		if (page.title === '') fail('missing-title', page.route, 'no <title>');
		else if (
			page.title.length < titleBand.min ||
			page.title.length > titleBand.max
		) {
			fail(
				'title-length',
				page.route,
				`${page.title.length} chars, band ${titleBand.min}–${titleBand.max}: ${JSON.stringify(page.title)}`
			);
		}

		if (page.description === '')
			fail('missing-description', page.route, 'no meta description');
		else if (
			page.description.length < descriptionBand.min ||
			page.description.length > descriptionBand.max
		) {
			fail(
				'description-length',
				page.route,
				`${page.description.length} chars, band ${descriptionBand.min}–${descriptionBand.max}`
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
		/*
		 * Equal, not merely present. Every page used to say `lang="en"` from one layout, so presence
		 * was the whole question; with three languages the failure that actually happens is a
		 * translated page that inherits the English attribute, which a screen reader then pronounces
		 * as English and a search engine files under the wrong language.
		 */
		const expectedLang = localeOf(page.route).lang;
		if (page.lang === '') fail('missing-lang', page.route, 'no lang on <html>');
		else if (page.lang !== expectedLang) {
			fail(
				'missing-lang',
				page.route,
				`<html lang="${page.lang}">, expected "${expectedLang}" for this route's language`
			);
		}

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

	/*
	 * --- counterpart anchors --------------------------------------------------------------------
	 * The language switcher carries `#hash` across, and a link shared between readers of different
	 * languages carries it too. Starlight slugifies heading text and keeps Cyrillic and Han
	 * characters, so a translated heading without an explicit `{#english-id}` gets a different id,
	 * and the deep link lands silently at the top of the page — nothing renders wrong, so nothing
	 * else here would notice. Checked from the English side only: English is what every
	 * translation is made from, and an id a translation adds is no link anybody holds.
	 *
	 * Counterparts are read from the page's own hreflang links rather than derived from the route,
	 * so this checks exactly the pairs the switcher offers. Every element id counts, not only
	 * headings', because a marketing view may put a section's id on its wrapper.
	 */
	const byRoute = new Map(pages.map((page) => [page.route, page]));
	for (const page of pages) {
		if (localeOf(page.route).key !== 'en') continue;
		const anchors = page.headings.flatMap((h) =>
			h.level >= 2 && h.level <= 4 && h.id ? [h.id] : []
		);
		if (anchors.length === 0) continue;

		const counterparts = new Set(
			page.alternates
				.map((alternate) => alternate.route)
				.filter((route) => route !== page.route)
		);
		for (const route of counterparts) {
			const counterpart = byRoute.get(route);
			if (!counterpart) continue;
			const present = new Set(counterpart.ids);
			for (const id of new Set(anchors)) {
				if (!present.has(id)) {
					fail(
						'counterpart-anchor',
						page.route,
						`#${id} has no element with that id on ${route}`
					);
				}
			}
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
		/*
		 * llms.txt is English only: a retrieval client reads one index, and listing every page three
		 * times would triple it with translations of what it already has.
		 */
		if (
			!llms.has(page.route) &&
			sectionFor(page.route) !== undefined &&
			localeOf(page.route).key === 'en'
		) {
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
	/*
	 * The blog is on this list for the reason the blog exists: it is written to be found and to
	 * persuade, which is exactly the surface the drift above happened on. Leaving it off would
	 * reopen the hole on the pages a prospect is most likely to read.
	 *
	 * An article genuinely about one backend is exempted, and the exemption is read from the page's
	 * own visible text rather than from a list kept here. That is the difference between this and
	 * the allowlist the comment above warns about: an article earns the exemption by telling the
	 * reader it is scoped, so it cannot be excused silently, and the excuse rots in public where
	 * somebody will see it. The sentence comes from `storageScope` in the article's front matter,
	 * which the content schema validates against the backends that actually ship.
	 *
	 * The scope is read from the line's `data-storage-scope` attribute rather than matched in its
	 * English wording, since the line is now written in three languages; and the line must still
	 * name the backend in its visible text. Datastore names are never translated, so that holds in
	 * every language, and it keeps the exemption something a reader can see.
	 */
	const scoped = (page: PageRecord): boolean =>
		page.storageScope !== undefined &&
		page.storageScope.backend !== '' &&
		page.storageScope.text.includes(page.storageScope.backend);
	const claimSurface = (page: PageRecord): boolean => {
		const route = stripLocale(page.route);
		return (
			route === '/' ||
			route.startsWith('/features/') ||
			(route.startsWith('/blog/') && !scoped(page))
		);
	};

	/*
	 * Chinese ends a sentence with a full-width mark and no space after it, so those marks split
	 * without requiring whitespace; the Latin marks still do, or "v1.4" and "e.g." would cut a
	 * sentence in two.
	 */
	const SENTENCE_END = /(?<=[.!?;])\s+|(?<=[。！？；])/;

	if (input.storageBackends.length > 1) {
		for (const page of indexable.filter(claimSurface)) {
			for (const sentence of page.text.split(SENTENCE_END)) {
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
