import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import starlightLlmsTxt from 'starlight-llms-txt';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
	site: 'https://foxauth.dev',
	integrations: [
		// Explicit so the styleguide (noindex, review-only) can be filtered out. Starlight detects
		// an existing sitemap integration and does not add its own second one.
		sitemap({ filter: (page) => !page.includes('/styleguide/') }),
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
