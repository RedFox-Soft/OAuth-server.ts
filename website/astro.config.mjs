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
			// The docs landing page (this task) links to Reference (Task 3) and to Get started /
			// Deploy (Task 4), none of which exist yet. The brief only calls for excluding
			// /docs/reference/**; widened here so `bun run build` succeeds before those tasks land.
			// Task 3 removes the reference exclude; Task 4 should remove the other two.
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
