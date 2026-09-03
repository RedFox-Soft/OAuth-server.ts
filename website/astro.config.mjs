import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import starlightLlmsTxt from 'starlight-llms-txt';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
	site: 'https://foxauth.dev',
	integrations: [
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
			// The docs landing page links to Get started / Deploy (Task 4), which don't exist yet.
			// /docs/reference/** stays excluded permanently, not just until this task lands: the six
			// Reference pages are src/pages/**/*.astro routes, not docs-collection Markdown/MDX, so
			// starlight-links-validator never has heading data for them (it only instruments the
			// markdown/MDX processor) and unconditionally reports InvalidLinkToCustomPage for a link
			// to any such route, whether or not the target exists — see validateLink() in
			// starlight-links-validator/libs/validation.ts. Task 4 should remove the other two.
			plugins: [
				starlightLinksValidator({
					exclude: [
						'/docs/reference/**',
						'/docs/get-started/**',
						'/docs/deploy/**'
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
