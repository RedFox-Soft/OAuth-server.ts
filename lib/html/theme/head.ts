import { FOX_PALETTE, MARK_MONO_CLASS } from './palette.js';

function declarations(scheme: 'light' | 'dark'): string {
	return Object.entries(FOX_PALETTE)
		.map(([role, value]) => `--fox-${role}:${value[scheme]};`)
		.join('');
}

/*
 * What every end-user page puts in its <head> (specs/096 contracts/page-head.md): the colour-scheme meta, which
 * also sets the canvas before any stylesheet arrives, and one block declaring the palette for both schemes.
 * The browser picks the scheme from the device's setting; nothing here reads a request.
 *
 * Built once: the string is constant, so its CSP hash is too. The `body` rule and the mark rule sit inside the
 * dark block only, so a light page is drawn exactly as before: a page that never set its own background or
 * text colour keeps the browser's. A monochrome provider mark keeps its own black fill in light — a CSS rule
 * out-ranks an SVG presentation attribute, so only the dark scheme recolours it.
 */
const THEME_HEAD =
	'<meta name="color-scheme" content="light dark"/>' +
	'<style>' +
	`:root{color-scheme:light dark;${declarations('light')}}` +
	`@media (prefers-color-scheme: dark){:root{${declarations('dark')}}` +
	'body{background:var(--fox-page);color:var(--fox-text)}' +
	`.${MARK_MONO_CLASS} [fill]{fill:var(--fox-mark-mono)}}` +
	'</style>';

export function themeHead(): string {
	return THEME_HEAD;
}
