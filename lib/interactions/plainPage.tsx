/*
 * The shell every plain interaction page shares. Extracted when the third caller arrived: the copies in
 * verifyPages.tsx and resetPages.tsx were byte-identical, and three copies of a page's document is where
 * "they all look the same" stops being true by accident.
 *
 * The inline styles deliberately mirror the antd shell pages (same field colour, card, radius and shadow),
 * so a page reached without the interaction cookie — or without the client bundle at all — does not look
 * like a different product.
 */

import { htmlResponse } from '../html/csp.js';

export function esc(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

// A page reporting a refusal passes its own status: a rendered error that answers 200 tells a non-browser
// client the opposite of what it says to a reader.
export function page(title: string, bodyHtml: string, status = 200): Response {
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>${esc(title)}</title></head><body style="font-family: Arial, Helvetica, sans-serif; background:#f0f2f5; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;"><div style="background:#fff; padding:32px; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.1); width:400px; text-align:center;">${bodyHtml}</div></body></html>`;
	return htmlResponse(html, { status });
}
