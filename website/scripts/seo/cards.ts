import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import {
	SECTION_ORDER,
	cardSlug,
	localeOf,
	sectionFor,
	type LocaleKey,
	type SectionName
} from '../../src/data/seo.ts';
import englishChrome from '../../src/i18n/messages/chrome/en.ts';
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

/*
 * Titles carry a site-name suffix for search results; a card shows the site name already. Chinese
 * titles use the full-width bar with no spaces around it, which is how the separator is set in
 * Han text.
 */
function cardTitle(title: string): string {
	return title.replace(/(?:\s+[—–|]\s+|\s*｜\s*)FoxAuth\s*$/, '').trim();
}

const WIDE =
	/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\u3000-\u303F\uFF00-\uFF60\uFFE0-\uFFE6]/u;

/*
 * How many Latin widths a title takes. A Han character is one code unit but sets about as wide as
 * two Latin letters, so measuring by `.length` put a Chinese title twice the intended size on the
 * card and ran it off the bottom.
 */
function displayWidth(text: string): number {
	let width = 0;
	for (const char of text) width += WIDE.test(char) ? 2 : 1;
	return width;
}

/** Fits the title to the card: short ones fill it, long ones still land on three lines or fewer. */
function fitSize(title: string): string {
	const width = displayWidth(title);
	if (width <= 28) return '76px';
	if (width <= 48) return '60px';
	return '48px';
}

type SectionLabels = Record<SectionName, string>;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

/*
 * The section names a card shows, in the page's language, from the same chrome messages the pages
 * use, so a card cannot name a section differently from the page it advertises. A language whose
 * module is not written yet falls back to English per name rather than failing the build: cards
 * are rendered for whatever was built, and the build has already decided what that is.
 */
async function sectionLabels(locale: LocaleKey): Promise<SectionLabels> {
	const english: SectionLabels = englishChrome.sections;
	if (locale === 'en') return english;
	let loaded: unknown;
	try {
		loaded = await import(`../../src/i18n/messages/chrome/${locale}.ts`);
	} catch {
		return english;
	}
	const sections =
		isRecord(loaded) && isRecord(loaded.default)
			? loaded.default.sections
			: undefined;
	if (!isRecord(sections)) return english;
	const out = { ...english };
	for (const name of SECTION_ORDER) {
		const label = sections[name];
		if (typeof label === 'string' && label !== '') out[name] = label;
	}
	return out;
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

		const labels = new Map<LocaleKey, SectionLabels>();
		for (const record of targets) {
			const locale = localeOf(record.route);
			let localeLabels = labels.get(locale.key);
			if (!localeLabels) {
				localeLabels = await sectionLabels(locale.key);
				labels.set(locale.key, localeLabels);
			}
			const section = sectionFor(record.route);
			const title = cardTitle(record.title);
			/*
			 * Only the English home card keeps its product line: it is written in English, and on a
			 * translated home page it would be the one English sentence on the card.
			 */
			const footnote =
				record.route === '/'
					? 'Built on OAuth-server.ts · Admin console · MCP for agents'
					: `${section ? localeLabels[section] : 'FoxAuth'} · foxauth.dev`;
			await page.evaluate(
				async ({ title, footnote, size, lang, cjk }) => {
					const tagline = document.querySelector<HTMLElement>('.tagline');
					const foot = document.querySelector('.footnote');
					/*
					 * The page's language on the card's root, so the browser picks Simplified Han glyph
					 * forms for a Chinese title rather than whichever CJK forms it defaults to.
					 */
					document.documentElement.lang = lang;
					if (tagline) {
						tagline.textContent = title;
						tagline.style.fontSize = size;
					}
					if (foot) foot.textContent = footnote;
					/*
					 * The CJK face is split by unicode-range and fetched only once some text needs a
					 * slice, which happens at layout — after this function would have returned, so the
					 * card would be shot in the fallback font. Loading the slices for this exact text
					 * first, then waiting, closes that gap.
					 */
					if (cjk) {
						await Promise.all([
							document.fonts.load(`500 ${size} "Noto Sans SC"`, title),
							document.fonts.load('500 24px "Noto Sans SC"', footnote)
						]);
						await document.fonts.ready;
					}
				},
				{
					title,
					footnote,
					lang: locale.lang,
					cjk: WIDE.test(title + footnote),
					/*
					 * The template's 40px is sized for its own two-line tagline. Page titles run from one
					 * word to a full sentence, and a short one set at 40px is lost on a 1200×630 card that
					 * a reader sees as a thumbnail, so the type is fitted to the title's width.
					 */
					size: fitSize(title)
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
			document.documentElement.lang = 'en';
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
