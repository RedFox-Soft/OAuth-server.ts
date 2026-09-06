import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { cardSlug, sectionFor } from '../../src/data/seo.ts';
import type { PageRecord } from './types.ts';

/*
 * One social card per page, rendered from scripts/og-template.html.
 *
 * This runs after the build rather than before it, because the set of pages is only known once
 * Astro has emitted them — deriving routes from the source tree instead would be a second route
 * derivation to keep in step with the first, which is the class of bug this feature exists to
 * remove. Cards are therefore written straight into dist/ rather than public/.
 *
 * The template is loaded once and only its two text slots are rewritten per page, so the whole set
 * costs one browser launch and one screenshot each.
 */

const HERE = fileURLToPath(new URL('.', import.meta.url));
const TEMPLATE = resolve(HERE, '../og-template.html');

/** Titles carry a site-name suffix for search results; a card shows the site name already. */
function cardTitle(title: string): string {
	return title.replace(/\s+[—–|]\s+FoxAuth\s*$/, '').trim();
}

/** Fits the title to the card: short ones fill it, long ones still land on three lines or fewer. */
function fitSize(title: string): string {
	if (title.length <= 28) return '76px';
	if (title.length <= 48) return '60px';
	return '48px';
}

export async function writeCards(
	dist: string,
	pages: PageRecord[]
): Promise<number> {
	const targets = pages.filter((page) => page.indexable);
	if (targets.length === 0) return 0;

	await mkdir(join(dist, 'og'), { recursive: true });
	const browser = await chromium.launch();
	let written = 0;

	try {
		const page = await browser.newPage({
			viewport: { width: 1200, height: 630 }
		});
		await page.goto(`file://${TEMPLATE}`);

		for (const record of targets) {
			const section = sectionFor(record.route);
			await page.evaluate(
				({ title, footnote, size }) => {
					const tagline = document.querySelector<HTMLElement>('.tagline');
					const foot = document.querySelector('.footnote');
					if (tagline) {
						tagline.textContent = title;
						tagline.style.fontSize = size;
					}
					if (foot) foot.textContent = footnote;
				},
				{
					title: cardTitle(record.title),
					footnote:
						record.route === '/'
							? 'Built on OAuth-server.ts · Admin console · MCP for agents'
							: `${section ?? 'FoxAuth'} · foxauth.dev`,
					/*
					 * The template's 40px is sized for its own two-line tagline. Page titles run from one
					 * word to a full sentence, and a short one set at 40px is lost on a 1200×630 card that
					 * a reader sees as a thumbnail, so the type is fitted to the title's length.
					 */
					size: fitSize(cardTitle(record.title))
				}
			);
			await page.screenshot({
				path: join(dist, 'og', `${cardSlug(record.route)}.png`),
				type: 'png'
			});
			written += 1;
		}

		// The shared fallback, for anything that references a card without having one of its own.
		await page.evaluate(() => {
			const tagline = document.querySelector('.tagline');
			if (tagline)
				tagline.textContent =
					'Source-available OAuth 2.1 / OIDC authorization server';
		});
		await page.screenshot({
			path: join(dist, 'og', 'default.png'),
			type: 'png'
		});
	} finally {
		await browser.close().catch(() => {});
	}

	return written;
}
