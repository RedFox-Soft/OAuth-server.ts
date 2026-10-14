import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';
import { EndUserTheme } from './provider.js';
import { themeHead } from './head.js';
import type { Language } from '../../i18n/languages.js';

interface Rule {
	selector: string;
	declarations: string[];
}

// Rules carrying antd custom properties, in order. Innermost braces only — a @keyframes block yields its steps,
// which carry no custom property and fall away.
function customPropertyRules(css: string): Rule[] {
	const rules: Rule[] = [];
	for (const [, selector, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
		const declarations = body
			.split(';')
			.map((d) => d.trim())
			.filter((d) => d.startsWith('--ant-'));
		if (declarations.length)
			rules.push({ selector: selector.trim(), declarations });
	}
	return rules;
}

const darkBlocks = new Map<string, string>();

/*
 * The dark scheme for an antd page, as one block of custom-property overrides (specs/096 research R1). With
 * the scope key fixed, antd's light and dark CSS differ in nothing but the values of `--ant-*` — so rendering
 * the page's own tree under the dark algorithm and keeping only those declarations is the whole dark theme,
 * with no change to markup and so none to hydration.
 *
 * Every selector gains `:root `. On a hydrated page cssinjs may append its own light block after this one, and
 * at equal specificity the later block would win; one pseudo-class more wins whatever the order.
 *
 * Memoized by the set of light selectors: the dark values for a given set of components never change while
 * the process runs, and the pages mount only a handful of combinations.
 */
function darkOverrides(
	page: ReactElement,
	lightCss: string,
	zeroRuntime: boolean
): string {
	const key = customPropertyRules(lightCss)
		.map((r) => r.selector)
		.sort()
		.join(',');
	const known = darkBlocks.get(key);
	if (known !== undefined) return known;

	const cache = createCache();
	renderToStaticMarkup(
		<StyleProvider cache={cache}>
			<EndUserTheme
				scheme="dark"
				zeroRuntime={zeroRuntime}
			>
				{page}
			</EndUserTheme>
		</StyleProvider>
	);
	const rules = customPropertyRules(extractStyle(cache, { plain: true }))
		.map((r) => `:root ${r.selector}{${r.declarations.join(';')}}`)
		.join('');
	const block = `<style>@media (prefers-color-scheme: dark){${rules}}</style>`;
	darkBlocks.set(key, block);
	return block;
}

/*
 * Renders an end-user page's antd tree in the end-user theme and returns its markup with everything its <head>
 * needs: the theme head, the page's own antd styles, and the dark block. The styles are extracted on the
 * server for the hydrated pages too — without them those pages painted with every antd colour undefined until
 * their bundle ran, and for good with scripts off (research R2).
 */
export function renderEndUserTree(
	page: ReactElement,
	{
		zeroRuntime = false,
		render = renderToStaticMarkup,
		language = 'en'
	}: {
		zeroRuntime?: boolean;
		render?: (element: ReactElement) => string;
		language?: Language;
	} = {}
): { html: string; head: string } {
	const cache = createCache();
	const html = render(
		<StyleProvider cache={cache}>
			<EndUserTheme
				zeroRuntime={zeroRuntime}
				language={language}
			>
				{page}
			</EndUserTheme>
		</StyleProvider>
	);
	const light = extractStyle(cache, { plain: true });
	return {
		html,
		head:
			themeHead() +
			extractStyle(cache) +
			darkOverrides(page, light, zeroRuntime)
	};
}
