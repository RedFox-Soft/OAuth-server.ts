import { mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { PageRecord } from './types.ts';

/*
 * A Markdown alternate for every indexable page, at the page's own address plus `.md`
 * (`/features/` → `/features.md`, `/` → `/index.md`). Appending `.md` is the form retrieval clients
 * probe first and needs nothing from the host, which matters on static hosting that cannot
 * negotiate on an Accept header.
 *
 * The body is the page's collected main content: no header, no footer, no navigation, no scripts.
 * Extracting it from the built HTML rather than from source keeps one path for MDX, Astro and the
 * generated Reference shells alike, and guarantees the alternate says what the page says.
 */

function alternatePath(route: string): string {
	if (route === '/') return 'index.md';
	return `${route.replace(/^\//, '').replace(/\/$/, '')}.md`;
}

function frontMatter(page: PageRecord): string {
	const lines = [
		'---',
		`title: ${JSON.stringify(page.title)}`,
		`description: ${JSON.stringify(page.description)}`,
		`canonical: ${JSON.stringify(page.canonical)}`
	];
	if (page.lastmod) lines.push(`lastmod: ${JSON.stringify(page.lastmod)}`);
	lines.push('---', '');
	return lines.join('\n');
}

export async function writeMarkdownAlternates(
	dist: string,
	pages: PageRecord[]
): Promise<number> {
	let written = 0;
	for (const page of pages) {
		if (!page.indexable) continue;
		const target = join(dist, alternatePath(page.route));
		await mkdir(dirname(target), { recursive: true });
		await Bun.write(target, `${frontMatter(page)}${page.text}\n`);
		written += 1;
	}
	return written;
}
