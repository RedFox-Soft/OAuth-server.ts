import type { APIRoute } from 'astro';
import { CRAWLERS, SITE_ORIGIN } from '../data/seo.ts';

export const prerender = true;

/*
 * robots.txt, generated from the typed list in data/seo.ts rather than kept as a static file in
 * public/. Two files answering the same request is the shape of bug this feature exists to remove,
 * so public/robots.txt was deleted rather than left alongside.
 *
 * Nothing is disallowed. Pages kept out of search say so with their own noindex, which is the
 * correct mechanism: a Disallow would stop a crawler ever reading that noindex, and a page with
 * inbound links can stay indexed on the strength of those alone. Nothing here is a security
 * control — everything the site publishes is already public.
 */
export const GET: APIRoute = () => {
	const lines = [
		'# Generated from website/src/data/seo.ts — edit the list there, not this file.',
		'',
		'User-agent: *',
		'Allow: /',
		''
	];

	if (CRAWLERS.length > 0) {
		lines.push(
			'# Assistant, answer-engine and AI-search crawlers, permitted by name. Being cited by',
			'# them is the point; the catch-all above already allows anything unlisted.'
		);
		for (const crawler of CRAWLERS) {
			lines.push(
				`# ${crawler.purpose} — verified ${crawler.verified} against ${crawler.source}`,
				`User-agent: ${crawler.agent}`,
				`${crawler.allow ? 'Allow' : 'Disallow'}: /`,
				''
			);
		}
	}

	lines.push(`Sitemap: ${SITE_ORIGIN}/sitemap-index.xml`, '');

	return new Response(lines.join('\n'), {
		headers: { 'Content-Type': 'text/plain; charset=utf-8' }
	});
};
