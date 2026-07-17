import { statSync } from 'node:fs';
import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import type { AdminContext } from '../auth/rbac.js';
import { Layout } from './pages/Layout.js';
import { Setup } from './pages/Setup.js';

const template = Bun.file('./lib/admin/ui/htmlTemplate.html');

// staticPlugin serves the bundle with a long max-age, so cache-bust it by the
// built file's mtime — a rebuilt admin.js is refetched, an unchanged one stays
// cached. Falls back to no version when the bundle isn't built (e.g. tests).
function bundleVersion(): string {
	try {
		return Math.trunc(statSync('./public/admin.js').mtimeMs).toString(36);
	} catch {
		return '';
	}
}

export async function renderAdminShell(props: {
	needsSetup: boolean;
	me: AdminContext | null;
}) {
	let html = await template.text();
	const version = bundleVersion();
	if (version) {
		html = html.replace('/public/admin.js', `/public/admin.js?v=${version}`);
	}
	html = html
		.replace(
			'<!--app-props-->',
			`<script>window.PROPS=${JSON.stringify(props)}</script>`
		)
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					{props.needsSetup ? <Setup /> : <Layout me={props.me} />}
				</StrictMode>
			)
		);
	return new Response(html, {
		headers: { 'content-type': 'text/html; charset=utf-8' }
	});
}
