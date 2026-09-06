import { join } from 'node:path';
import {
	SECTION_ORDER,
	sectionFor,
	type SectionName
} from '../../src/data/seo.ts';
import type { LlmsEntry, PageRecord } from './types.ts';

/*
 * The whole-site machine-readable index, written over the one starlight-llms-txt emits.
 *
 * That plugin's llms.txt route enumerates no pages at all — it emits the title, the description,
 * links to the small and full variants, a fixed notes block and an optional-links section, and no
 * configuration changes that. Its llms-full.txt is built from the docs collection alone, so the
 * pricing, features, comparison and contact pages were invisible to a retrieval client entirely.
 *
 * Overwriting the built file rather than replacing the route keeps the plugin's MDX-aware renderer
 * for the documentation body, which is the part it does well.
 */

/* Marks the start of the section this script owns inside the plugin's llms-full.txt. */
const SENTINEL = '<!-- foxauth:non-docs-pages -->';

const SITE_TITLE = 'FoxAuth';
const SITE_SUMMARY =
	'Source-available OAuth 2.1 and OpenID Connect authorization server, built on OAuth-server.ts. ' +
	'Self-hosted or cloud-managed, with an admin console and an MCP control plane an AI agent can drive.';

export class UnclassifiedRoute extends Error {
	constructor(route: string) {
		super(
			`Route ${route} matches no section in src/data/seo.ts.\n` +
				'Classify it there — an unclassified page is one nobody will notice is missing from the index.'
		);
		this.name = 'UnclassifiedRoute';
	}
}

/** Titles carry a " — FoxAuth" suffix for search results; the index has the site name already. */
function label(title: string): string {
	return title.replace(/\s+[—–|]\s+FoxAuth\s*$/, '').trim();
}

export function indexEntries(pages: PageRecord[]): LlmsEntry[] {
	const entries: LlmsEntry[] = [];
	for (const page of pages) {
		if (!page.indexable) continue;
		const section = sectionFor(page.route);
		if (!section) throw new UnclassifiedRoute(page.route);
		entries.push({
			url: page.canonical,
			label: label(page.title),
			summary: page.description,
			section
		});
	}
	return entries;
}

function bySection(entries: LlmsEntry[], section: SectionName): LlmsEntry[] {
	return entries
		.filter((entry) => entry.section === section)
		.sort((a, b) => a.url.localeCompare(b.url));
}

export function renderIndex(entries: LlmsEntry[], origin: string): string {
	const out = [`# ${SITE_TITLE}`, '', `> ${SITE_SUMMARY}`, ''];

	for (const section of SECTION_ORDER) {
		const inSection = bySection(entries, section);
		if (inSection.length === 0) continue;
		out.push(`## ${section}`, '');
		for (const entry of inSection) {
			out.push(`- [${entry.label}](${entry.url}): ${entry.summary}`);
		}
		out.push('');
	}

	out.push(
		'## Full text',
		'',
		`- [Complete site](${origin}/llms-full.txt): every page above, in full.`,
		`- [Abridged documentation](${origin}/llms-small.txt): the documentation with non-essential content removed.`,
		'',
		'Every page is also available on its own as Markdown, at the page address plus `.md`',
		`— for example ${origin}/features.md.`,
		''
	);

	return out.join('\n');
}

/*
 * The pages starlight-llms-txt never sees, appended to its documentation body. Selected by route
 * prefix rather than by section: /docs/get-started/ is presented as "Start here" in the index but is
 * still a docs-collection page the plugin has already rendered, and filtering by section duplicated
 * all five of them.
 */
function nonDocsBody(pages: PageRecord[]): string {
	const chosen = pages
		.filter((page) => page.indexable && !page.route.startsWith('/docs/'))
		.sort((a, b) => a.route.localeCompare(b.route));

	return chosen
		.map(
			(page) =>
				`# ${label(page.title)}\n\nSource: ${page.canonical}\n\n${page.text}`
		)
		.join('\n\n---\n\n');
}

export async function writeLlmsFiles(
	dist: string,
	pages: PageRecord[],
	origin: string
): Promise<{ entries: number; fullBytes: number }> {
	const entries = indexEntries(pages);
	await Bun.write(join(dist, 'llms.txt'), renderIndex(entries, origin));

	const fullPath = join(dist, 'llms-full.txt');
	const existing = await Bun.file(fullPath)
		.text()
		.catch(() => '');
	/*
	 * The plugin's output is appended to rather than replaced, so this must be idempotent: running
	 * postbuild twice against one dist/ otherwise stacked a second copy of every non-docs page. The
	 * sentinel marks where our section starts, and everything from it is rewritten each time.
	 */
	const docsOnly = existing.split(SENTINEL)[0].trimEnd();
	const combined = `${docsOnly}\n\n${SENTINEL}\n\n${nonDocsBody(pages)}\n`;
	await Bun.write(fullPath, combined);

	return { entries: entries.length, fullBytes: Buffer.byteLength(combined) };
}
