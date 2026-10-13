import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { END_USER_PAGES, type PageFamily } from '../end_user_pages.ts';

const FAMILIES: readonly PageFamily[] = ['hydrated', 'terminal'];

// The one terminal page with no antd in it: a bare form that submits itself. The theme head alone covers it.
const WITHOUT_ANTD = new Set(['auto-submit callback']);

const DARK_MEDIA = '@media (prefers-color-scheme: dark){';

interface Rule {
	selector: string;
	declarations: string[];
}

function rules(css: string): Rule[] {
	return [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map(([, s, body]) => ({
		selector: s.trim(),
		declarations: body
			.split(';')
			.map((d) => d.trim())
			.filter(Boolean)
	}));
}

function styleBlocks(html: string): string[] {
	return [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map(
		(m) => m[1]
	);
}

// The antd blocks that hold custom properties outside any media query: what a light page paints with.
function lightRules(html: string): Rule[] {
	return styleBlocks(html)
		.filter((b) => !b.startsWith(DARK_MEDIA))
		.flatMap(rules)
		.filter((r) => r.declarations.some((d) => d.startsWith('--ant-')));
}

function darkBlocks(html: string): string[] {
	return styleBlocks(html).filter(
		(b) => b.startsWith(DARK_MEDIA) && b.includes('--ant-')
	);
}

function value(rule: Rule | undefined, property: string): string | undefined {
	return rule?.declarations
		.find((d) => d.startsWith(`${property}:`))
		?.slice(property.length + 1);
}

/**
 * @proves An antd page is dark from its first paint for a person whose device prefers dark: the page arrives
 * with antd's colours already defined — before, and without, any script — and with one block that redefines
 * every one of them for the dark scheme, and nothing else (specs/096 FR-002, FR-003).
 */
describe('an antd page arrives with both schemes defined', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [name, family, render] of END_USER_PAGES) {
		if (!FAMILIES.includes(family) || WITHOUT_ANTD.has(name)) continue;

		it(`defines antd’s colours in the ${name} page as served`, async () => {
			const html = await (await render()).text();

			const root = lightRules(html).find((r) => r.selector === '.fox');
			expect(value(root, '--ant-color-text')).toBeDefined();
		});

		it(`redefines every antd colour of the ${name} page for the dark scheme, and only that`, async () => {
			const html = await (await render()).text();

			const dark = darkBlocks(html);
			expect(dark).toHaveLength(1);
			const darkRules = rules(dark[0].slice(DARK_MEDIA.length, -1));
			expect(darkRules.map((r) => r.selector).sort()).toEqual(
				lightRules(html)
					.map((r) => `:root ${r.selector}`)
					.sort()
			);
			for (const rule of darkRules)
				for (const d of rule.declarations) expect(d).toStartWith('--ant-');

			const root = darkRules.find((r) => r.selector === ':root .fox');
			expect(value(root, '--ant-color-bg-container')).toBe('#141414');
			expect(value(root, '--ant-color-text')).toBe('rgba(255,255,255,0.85)');
		});
	}
});
