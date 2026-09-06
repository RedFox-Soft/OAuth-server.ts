import { join } from 'node:path';
import type { PageRecord } from './types.ts';

/*
 * The image sitemap, written by hand rather than through the sitemap integration.
 *
 * @astrojs/sitemap types its serialize payload as
 * Pick<SitemapItemLoose, 'url' | 'lastmod' | 'changefreq' | 'priority' | 'links'> — `img` is
 * excluded — so emitting image entries through it would require a type assertion. The integration's
 * own `customSitemaps` option appends this file to the sitemap index instead, which is the
 * supported path and costs no escape from the type system.
 *
 * Selection is by construction, not by a filter list: only <figure>-wrapped images are collected,
 * and ScreenshotFigure.astro is the one component that emits a figure. The header logo is not in a
 * figure and the social cards are never in the DOM, so neither can leak in. On a build with the
 * capture skipped the figures do not render at all, and this file is written empty rather than
 * claiming images the pages do not show.
 */

function escapeXml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&apos;');
}

export function renderImageSitemap(
	pages: PageRecord[],
	origin: string
): string {
	const entries = pages
		.filter((page) => page.indexable && page.images.length > 0)
		.map((page) => {
			const images = page.images
				.map((image) => {
					const loc = new URL(image.src, origin).href;
					// The caption a reader sees is the better index signal; alt is the fallback, and one
					// of the two is always present because a figure without either fails the guardrail.
					const caption = image.caption ?? image.alt;
					return [
						'\t\t<image:image>',
						`\t\t\t<image:loc>${escapeXml(loc)}</image:loc>`,
						`\t\t\t<image:caption>${escapeXml(caption)}</image:caption>`,
						'\t\t</image:image>'
					].join('\n');
				})
				.join('\n');
			return `\t<url>\n\t\t<loc>${escapeXml(page.canonical)}</loc>\n${images}\n\t</url>`;
		});

	return [
		'<?xml version="1.0" encoding="UTF-8"?>',
		'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">',
		...entries,
		'</urlset>',
		''
	].join('\n');
}

export async function writeImageSitemap(
	dist: string,
	pages: PageRecord[],
	origin: string
): Promise<number> {
	const xml = renderImageSitemap(pages, origin);
	await Bun.write(join(dist, 'sitemap-images.xml'), xml);
	return pages
		.filter((page) => page.indexable)
		.reduce((count, page) => count + page.images.length, 0);
}
