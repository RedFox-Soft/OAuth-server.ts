import { readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { normaliseRoute } from '../../src/data/seo.ts';
import { lastModified } from './lastmod.ts';
import { sourcesFor } from './sources.ts';
import type { ImageRecord, PageRecord, StructuredEntity } from './types.ts';

/*
 * One PageRecord per built page, read from the HTML that actually shipped rather than from the
 * sources that produced it. That is deliberate: it is the only reading that covers hand-written
 * pages, content-collection pages and the generated Reference shells on identical terms, and it
 * validates what a crawler will really see.
 */

async function htmlFiles(dist: string): Promise<string[]> {
	const found: string[] = [];
	async function walk(dir: string): Promise<void> {
		for (const entry of await readdir(dir, { withFileTypes: true })) {
			const full = join(dir, entry.name);
			if (entry.isDirectory()) await walk(full);
			else if (entry.name.endsWith('.html')) found.push(full);
		}
	}
	await walk(dist);
	return found.sort();
}

function routeOf(dist: string, file: string): string {
	const rel = relative(dist, file).split(sep).join('/');
	return normaliseRoute(`/${rel}`);
}

interface Draft {
	title: string;
	description: string;
	canonical: string;
	lang: string;
	robots: string;
	og: Record<string, string>;
	twitter: Record<string, string>;
	headings: { level: number; text: string }[];
	images: ImageRecord[];
	links: string[];
	jsonLd: string[];
	text: string[];
}

function parseStructured(raw: string): StructuredEntity[] {
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return [{ type: 'invalid-json', props: {}, assertedStrings: [] }];
	}
	const blocks = Array.isArray(parsed) ? parsed : [parsed];
	return blocks.filter(isRecord).map((block) => ({
		type: typeof block['@type'] === 'string' ? block['@type'] : 'missing-type',
		props: block,
		assertedStrings: assertedStringsOf(block)
	}));
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const NAMED_ENTITIES: Record<string, string> = {
	amp: '&',
	lt: '<',
	gt: '>',
	quot: '"',
	apos: "'",
	nbsp: ' ',
	mdash: '—',
	ndash: '–',
	hellip: '…',
	rsquo: '’',
	lsquo: '‘',
	ldquo: '“',
	rdquo: '”'
};

/*
 * HTMLRewriter hands back source text with character references intact, so an apostrophe arrives as
 * `&#39;`. Left alone it survives into the image sitemap re-escaped as `&amp;#39;` and into the
 * containment check as a string no page visibly says. Decoded once, here, where the text is read.
 */
function decodeEntities(value: string): string {
	return value.replace(
		/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g,
		(match, ref: string) => {
			if (ref.startsWith('#x') || ref.startsWith('#X')) {
				return String.fromCodePoint(Number.parseInt(ref.slice(2), 16));
			}
			if (ref.startsWith('#'))
				return String.fromCodePoint(Number.parseInt(ref.slice(1), 10));
			return NAMED_ENTITIES[ref.toLowerCase()] ?? match;
		}
	);
}

/*
 * The human-readable claims a block makes. Kept to strings a page would visibly say — names,
 * questions, answers, breadcrumb labels — because these are what the containment rule checks. URLs,
 * dates and identifiers are excluded: they are true without being written on the page.
 */
function assertedStringsOf(block: Record<string, unknown>): string[] {
	const out: string[] = [];
	const push = (value: unknown): void => {
		if (typeof value === 'string' && value.trim() !== '')
			out.push(value.trim());
	};

	const type = block['@type'];
	if (type === 'SoftwareApplication') {
		push(block.name);
		push(block.license);
	} else if (type === 'Organization') {
		push(block.name);
	} else if (type === 'TechArticle') {
		push(block.headline);
	} else if (type === 'FAQPage') {
		const entities = Array.isArray(block.mainEntity) ? block.mainEntity : [];
		for (const q of entities.filter(isRecord)) {
			push(q.name);
			const answer = q.acceptedAnswer;
			if (isRecord(answer)) push(answer.text);
		}
	}
	/*
	 * BreadcrumbList asserts nothing: its names are navigation labels describing where the page sits,
	 * not claims the page makes about its subject. Requiring "Home" to appear in the body text would
	 * only force a visible breadcrumb widget onto every page to satisfy a rule, which is the rule
	 * bending the site rather than protecting it.
	 */
	return out;
}

async function parsePage(file: string): Promise<Draft> {
	const draft: Draft = {
		title: '',
		description: '',
		canonical: '',
		lang: '',
		robots: '',
		og: {},
		twitter: {},
		headings: [],
		images: [],
		links: [],
		jsonLd: [],
		text: []
	};

	// A <figure> is the site's marker for substantive imagery: only ScreenshotFigure.astro emits
	// one, so the logo and the social cards are excluded without a filter list to maintain.
	let figure: ImageRecord | undefined;
	// <main>'s text handler receives every descendant text node, script bodies included.
	let suppressText = 0;
	let titleOpen = false;
	let jsonLdOpen = false;

	const rewriter = new HTMLRewriter()
		.on('html', {
			element(el) {
				draft.lang = el.getAttribute('lang') ?? '';
			}
		})
		.on('head > title', {
			element() {
				titleOpen = true;
			},
			text(t) {
				if (titleOpen) draft.title += t.text;
			}
		})
		.on('meta', {
			element(el) {
				const name = el.getAttribute('name');
				const property = el.getAttribute('property');
				const content = el.getAttribute('content') ?? '';
				if (name === 'description') draft.description = content;
				else if (name === 'robots') draft.robots = content;
				else if (name?.startsWith('twitter:'))
					draft.twitter[name.slice(8)] = content;
				else if (property?.startsWith('og:'))
					draft.og[property.slice(3)] = content;
			}
		})
		.on('link[rel="canonical"]', {
			element(el) {
				draft.canonical = el.getAttribute('href') ?? '';
			}
		})
		.on('h1, h2, h3, h4, h5, h6', {
			element(el) {
				draft.headings.push({ level: Number(el.tagName.slice(1)), text: '' });
			},
			text(t) {
				const last = draft.headings.at(-1);
				if (last) last.text += t.text;
			}
		})
		.on('figure', {
			element(el) {
				figure = undefined;
				el.onEndTag(() => {
					if (figure) draft.images.push(figure);
					figure = undefined;
				});
			}
		})
		.on('figure img', {
			element(el) {
				const width = el.getAttribute('width');
				const height = el.getAttribute('height');
				figure = {
					src: el.getAttribute('src') ?? '',
					alt: el.getAttribute('alt') ?? '',
					width: width ? Number(width) : undefined,
					height: height ? Number(height) : undefined,
					loading: el.getAttribute('loading') ?? undefined
				};
			}
		})
		.on('figure figcaption', {
			text(t) {
				if (figure) figure.caption = `${figure.caption ?? ''}${t.text}`;
			}
		})
		.on('a[href]', {
			element(el) {
				draft.links.push(el.getAttribute('href') ?? '');
			}
		})
		.on('script[type="application/ld+json"]', {
			element() {
				jsonLdOpen = true;
				draft.jsonLd.push('');
			},
			text(t) {
				if (jsonLdOpen) draft.jsonLd[draft.jsonLd.length - 1] += t.text;
			}
		})
		.on('main script, main style, main noscript', {
			element(el) {
				suppressText += 1;
				el.onEndTag(() => {
					suppressText -= 1;
				});
			}
		})
		// Text arrives as bare chunks with no structure, so an eyebrow and the heading beneath it
		// would otherwise concatenate into one word. A break at each block start keeps the extracted
		// text readable, which matters because it is also what the Markdown alternates are built from.
		.on(
			'main p, main h1, main h2, main h3, main h4, main h5, main h6, main li, main tr, main figcaption, main pre, main blockquote, main section, main article, main header, main footer, main div',
			{
				element() {
					if (suppressText === 0) draft.text.push('\n');
				}
			}
		)
		.on('main', {
			text(t) {
				if (suppressText === 0) draft.text.push(t.text);
			}
		});

	await rewriter.transform(new Response(await Bun.file(file).text())).text();
	return draft;
}

/*
 * Line structure is kept — the Markdown alternates are built from this — so only horizontal
 * whitespace is collapsed. Rules that need a flat string for substring matching flatten it
 * themselves via `flatten()`.
 */
function normaliseText(chunks: string[]): string {
	return decodeEntities(chunks.join(''))
		.replace(/[^\S\n]+/g, ' ')
		.split('\n')
		.map((line) => line.trim())
		.filter((line, i, all) => line !== '' || all[i - 1] !== '')
		.join('\n')
		.trim();
}

/** One-line form for substring checks, where the page's line breaks are noise. */
export function flatten(text: string): string {
	return text.replace(/\s+/g, ' ').trim();
}

/** In-site links only, reduced to the route form every other surface compares against. */
function inSiteRoutes(hrefs: string[], origin: string): string[] {
	const routes = new Set<string>();
	for (const href of hrefs) {
		if (href.startsWith('#') || href.startsWith('mailto:')) continue;
		let path: string | undefined;
		if (href.startsWith('/')) path = href;
		else if (href.startsWith(origin)) path = href.slice(origin.length) || '/';
		if (path === undefined) continue;
		const withoutHash = path.split('#')[0].split('?')[0];
		if (withoutHash === '') continue;
		if (/\.(png|svg|ico|txt|xml|json|md|jpg|webp)$/.test(withoutHash)) continue;
		routes.add(normaliseRoute(withoutHash));
	}
	return [...routes];
}

export async function collectPages(
	dist: string,
	origin: string
): Promise<PageRecord[]> {
	const files = await htmlFiles(dist);
	const records: PageRecord[] = [];

	for (const file of files) {
		const route = routeOf(dist, file);
		const draft = await parsePage(file);
		const { sourceFile, dataSources } = sourcesFor(route);

		records.push({
			route,
			file: relative(dist, file).split(sep).join('/'),
			sourceFile,
			dataSources,
			title: decodeEntities(draft.title).trim(),
			description: decodeEntities(draft.description).trim(),
			canonical: draft.canonical.trim(),
			lang: draft.lang.trim(),
			indexable: !/noindex/i.test(draft.robots),
			ogImage: draft.og.image ?? '',
			ogTitle: decodeEntities(draft.og.title ?? ''),
			ogDescription: decodeEntities(draft.og.description ?? ''),
			ogUrl: draft.og.url ?? '',
			twitterCard: draft.twitter.card ?? '',
			lastmod: lastModified(sourceFile, dataSources),
			headings: draft.headings.map((h) => ({
				level: h.level,
				text: decodeEntities(h.text).trim()
			})),
			images: draft.images.map((img) => ({
				...img,
				alt: decodeEntities(img.alt),
				caption: decodeEntities(img.caption ?? '').trim() || undefined
			})),
			outboundLinks: inSiteRoutes(draft.links, origin),
			structured: draft.jsonLd.flatMap(parseStructured),
			text: normaliseText(draft.text)
		});
	}

	return records;
}
