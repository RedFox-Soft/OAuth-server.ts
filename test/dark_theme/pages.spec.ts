import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	ADMIN_SHELL,
	END_USER_PAGES,
	type PageFamily
} from '../end_user_pages.ts';
import { themeHead } from 'lib/html/theme/head.ts';

// The families whose pages follow the scheme so far; each story widens it (specs/096 tasks).
const FAMILIES: readonly PageFamily[] = ['hydrated', 'terminal', 'plain'];

const COLOUR_LITERAL = /#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/i;

function styleAttributes(html: string): string[] {
	return [...html.matchAll(/\sstyle="([^"]*)"/g)].map((m) => m[1]);
}

/**
 * @proves A person whose device prefers dark gets every end-user page dark: each page declares the palette for
 * both schemes and lets the browser choose, and no colour on it is fixed to the light scheme — so the person is
 * never thrown from a dark page into a white one (specs/096 FR-001, FR-002, FR-009).
 */
describe('an end-user page follows the device’s colour scheme', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [name, family, render] of END_USER_PAGES) {
		if (!FAMILIES.includes(family)) continue;

		it(`lets the browser draw the ${name} page in either scheme`, async () => {
			const html = await (await render()).text();

			expect(html).toContain(
				'<meta name="color-scheme" content="light dark"/>'
			);
			expect(html.split(themeHead()).length - 1).toBe(1);
		});

		it(`fixes no colour of the ${name} page to the light scheme`, async () => {
			const html = await (await render()).text();

			const fixed = styleAttributes(html).filter((s) => COLOUR_LITERAL.test(s));
			expect(fixed).toEqual([]);
		});
	}

	it('leaves the administrator console as it was', async () => {
		const html = await (await ADMIN_SHELL()).text();

		expect(html).not.toContain('color-scheme');
		expect(html).not.toContain('--fox-');
		expect(html).not.toContain('prefers-color-scheme');
	});
});
