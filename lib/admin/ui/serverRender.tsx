import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import type { AdminContext } from '../auth/rbac.js';
import { Layout } from './pages/Layout.js';
import { Setup } from './pages/Setup.js';

const template = Bun.file('./lib/admin/ui/htmlTemplate.html');

export async function renderAdminShell(props: {
	needsSetup: boolean;
	me: AdminContext | null;
}) {
	let html = await template.text();
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
