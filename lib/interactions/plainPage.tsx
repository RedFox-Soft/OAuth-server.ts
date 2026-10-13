/*
 * The shell every plain interaction page shares. Extracted when the third caller arrived: the copies in
 * verifyPages.tsx and resetPages.tsx were byte-identical, and three copies of a page's document is where
 * "they all look the same" stops being true by accident.
 *
 * The inline styles deliberately mirror the antd shell pages (same field colour, card, radius and shadow),
 * so a page reached without the interaction cookie — or without the client bundle at all — does not look
 * like a different product. Every colour is a palette role, declared by the theme head for both colour
 * schemes, so these pages follow the device's scheme with no script, as the antd pages do (specs/096).
 */

import { htmlResponse } from '../html/csp.js';
import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import { themeHead } from '../html/theme/head.js';

// A page reporting a refusal passes its own status: a rendered error that answers 200 tells a non-browser
// client the opposite of what it says to a reader.
//
// The card is fluid up to its width, inside a 16 px gutter: a fixed width wider than a 320 px phone scrolled
// every plain page sideways (WCAG 1.4.10). `wide` is for a page that lists things — the connected-applications
// page (specs/095) — which reads from the top and left rather than as one centred message.
export function page(
	title: string,
	bodyHtml: string,
	status = 200,
	{ denyFraming, wide }: { denyFraming?: boolean; wide?: boolean } = {}
): Response {
	const layout = wide
		? 'align-items:flex-start; justify-content:center; padding:32px 16px;'
		: 'align-items:center; justify-content:center; padding:16px;';
	const card = wide
		? 'max-width:640px; text-align:left;'
		: 'max-width:400px; text-align:center;';
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>${esc(title)}</title>${themeHead()}</head><body style="font-family: Arial, Helvetica, sans-serif; background:${foxVar('page')}; margin:0; min-height:100vh; box-sizing:border-box; display:flex; ${layout}"><div style="background:${foxVar('card')}; padding:32px; border-radius:12px; box-shadow:0 2px 8px ${foxVar('shadow')}; width:100%; box-sizing:border-box; ${card}">${bodyHtml}</div></body></html>`;
	return htmlResponse(html, { status, denyFraming });
}
