import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SITE_ORIGIN, normaliseRoute } from '../src/data/seo.ts';
import { collectPages } from './seo/collect.ts';
import { writeImageSitemap } from './seo/image_sitemap.ts';
import { writeLlmsFiles } from './seo/llms.ts';
import { writeMarkdownAlternates } from './seo/markdown.ts';
import { freshnessReport, freshnessWarning } from './seo/freshness.ts';
import { report, verify } from './seo/verify.ts';

/*
 * Everything that happens to dist/ after Astro has written it, in dependency order.
 *
 * The pages are collected once, here, and the same records feed every generator and the verifier.
 * That is what stops the sitemap, the machine-readable index and the guardrail drifting apart: they
 * are not three readings of the site, they are three consumers of one reading.
 */

const HERE = fileURLToPath(new URL('.', import.meta.url));
const DIST = resolve(HERE, '../dist');

function routesIn(xml: string): string[] {
	return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) =>
		normaliseRoute(new URL(match[1]).pathname)
	);
}

async function readIfPresent(path: string): Promise<string> {
	return existsSync(path) ? Bun.file(path).text() : '';
}

async function main(): Promise<void> {
	const pages = await collectPages(DIST, SITE_ORIGIN);
	console.log(`seo: collected ${pages.length} pages`);

	const images = await writeImageSitemap(DIST, pages, SITE_ORIGIN);
	console.log(`seo: sitemap-images.xml — ${images} images`);

	const { entries, fullBytes } = await writeLlmsFiles(DIST, pages, SITE_ORIGIN);
	console.log(
		`seo: llms.txt — ${entries} pages; llms-full.txt — ${(fullBytes / 1024).toFixed(0)} KB`
	);

	const alternates = await writeMarkdownAlternates(DIST, pages);
	console.log(`seo: ${alternates} Markdown alternates`);

	/*
	 * Cards are rendered here, not in the pre-build capture, because the page set is only known once
	 * Astro has emitted it. SITE_SKIP_CAPTURE is the documented fast local build; it leaves the cards
	 * unrendered, and the verifier reports the image rule as skipped rather than passing it silently.
	 */
	const cardsAvailable = process.env.SITE_SKIP_CAPTURE !== '1';
	if (cardsAvailable) {
		const { writeCards } = await import('./seo/cards.ts');
		const cards = await writeCards(DIST, pages);
		console.log(`seo: ${cards} social cards`);
	}

	const sitemapXml = await readIfPresent(join(DIST, 'sitemap-0.xml'));
	const imageXml = await readIfPresent(join(DIST, 'sitemap-images.xml'));
	const llmsTxt = await readIfPresent(join(DIST, 'llms.txt'));

	const result = verify({
		dist: DIST,
		origin: SITE_ORIGIN,
		pages,
		sitemapRoutes: routesIn(sitemapXml),
		imageSitemapRoutes: routesIn(imageXml),
		llmsUrls: [...llmsTxt.matchAll(/\]\((https:\/\/[^)]+\/)\)?:/g)].map(
			(m) => m[1]
		),
		cardsAvailable
	});

	for (const note of result.skipped) console.log(`seo: skipped ${note}`);

	/*
	 * Reported, never enforced. Staleness is the passage of time rather than a mistake anyone
	 * made, and failing a build on it would block work unrelated to the page — so this prints
	 * and the build carries on. The page's own notice is the signal that actually gets acted on.
	 */
	const freshness = freshnessReport(pages);
	const warning = freshnessWarning(freshness);
	if (warning) console.warn(warning);
	else if (freshness.length > 0) {
		console.log(
			`seo: ${freshness.length} comparisons, all within the freshness limit`
		);
	}

	if (result.violations.length > 0) {
		console.error(
			`\nSEO check failed: ${result.violations.length} violations\n`
		);
		console.error(report(result));
		console.error('');
		process.exit(1);
	}

	console.log(`seo: ${pages.length} pages checked, no violations`);
}

await main();
