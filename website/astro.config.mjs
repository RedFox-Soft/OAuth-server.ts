import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import starlightLlmsTxt from 'starlight-llms-txt';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';
import { SITE_ORIGIN, isIndexable, normaliseRoute } from './src/data/seo.ts';
import { lastModified } from './scripts/seo/lastmod.ts';
import { sourcesFor } from './scripts/seo/sources.ts';

export default defineConfig({
	site: SITE_ORIGIN,
	// Dev only (the build is static). Vite binds the first address `localhost` resolves to, which on
	// Node ≥ 17 is `::1` alone — a browser or proxy that resolves localhost to 127.0.0.1 then gets
	// "connection refused". `true` listens on both families.
	server: { host: true },
	integrations: [
		// Explicit so pages kept out of search can be filtered out, and so Starlight does not add a
		// second sitemap of its own. The filter reads the same non-indexable list src/data/seo.ts
		// gives Seo.astro: before that, a page was told "noindex" in one file and advertised in the
		// sitemap by a separate string match in this one, with nothing keeping the two in step.
		//
		// `serialize` supplies a per-page lastmod from git. The integration's global `lastmod` option
		// would stamp one date on every entry, which tells a crawler nothing except to stop trusting
		// the field. `changefreq` and `priority` are deliberately absent — Google ignores both.
		//
		// customSitemaps carries the image sitemap, which scripts/seo/image_sitemap.ts writes after
		// the build. It cannot be produced here: the integration's SitemapItem type is a Pick that
		// excludes `img`, so returning image entries from serialize would need a type assertion.
		sitemap({
			filter: (page) => isIndexable(new URL(page).pathname),
			customSitemaps: [`${SITE_ORIGIN}/sitemap-images.xml`],
			namespaces: { image: true, news: false, video: false, xhtml: false },
			serialize: (item) => {
				const route = normaliseRoute(new URL(item.url).pathname);
				const { sourceFile, dataSources } = sourcesFor(route);
				const lastmod = lastModified(sourceFile, dataSources);
				return lastmod ? { ...item, lastmod } : item;
			}
		}),
		starlight({
			title: 'FoxAuth',
			description:
				'Source-available OAuth 2.1 and OpenID Connect authorization server, built on OAuth-server.ts.',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/RedFox-Soft/OAuth-server.ts'
				}
			],
			customCss: ['./src/styles/global.css'],
			// Starlight renders its own <head>, so docs pages never reach Seo.astro. The override
			// renders Starlight's head unchanged and adds only what it leaves out: the social card,
			// the structured data, the last-modified signal and the Markdown alternate.
			components: { Head: './src/components/StarlightHead.astro' },
			// src/pages/404.astro is the site's one not-found page, so Starlight's own 404 route is a
			// duplicate static route — Astro warns today and says it becomes a hard error later.
			disable404Route: true,
			// Everything excluded here is a src/pages/**/*.astro route rather than docs-collection
			// Markdown/MDX: the six Reference pages, the three root documents rendered from the
			// repository's own CHANGELOG/SECURITY/LICENSE, and the marketing pages (features,
			// pricing, compare, contact). starlight-links-validator only instruments
			// the markdown/MDX processor, so it never has heading data for such a route and
			// unconditionally reports InvalidLinkToCustomPage for a link to one, whether or not the
			// target exists — see validateLink() in starlight-links-validator/libs/validation.ts.
			// The exclusion is permanent for that reason, not a placeholder. Docs-collection links
			// (/docs/get-started/**, /docs/deploy/**) are validated normally.
			plugins: [
				starlightLinksValidator({
					exclude: [
						'/docs/reference/**',
						'/changelog/',
						'/security/',
						'/license/',
						'/features/',
						'/pricing/',
						'/compare/**',
						'/contact/'
					]
				}),
				starlightLlmsTxt()
			],
			sidebar: [
				{
					label: 'Get started',
					items: [{ autogenerate: { directory: 'docs/get-started' } }]
				},
				{
					label: 'Deploy',
					items: [{ autogenerate: { directory: 'docs/deploy' } }]
				},
				{
					label: 'Security',
					items: [{ autogenerate: { directory: 'docs/security' } }]
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Settings', link: '/docs/reference/settings/' },
						{ label: 'Endpoints', link: '/docs/reference/endpoints/' },
						{ label: 'Admin API', link: '/docs/reference/admin-api/' },
						{ label: 'MCP tools', link: '/docs/reference/mcp-tools/' },
						{ label: 'Addon seams', link: '/docs/reference/addon-seams/' },
						{
							label: 'Environment variables',
							link: '/docs/reference/environment/'
						}
					]
				}
			]
		})
	],
	vite: { plugins: [tailwindcss()] }
});
