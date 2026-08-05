import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import type { AdminContext } from '../auth/rbac.js';
import { Layout } from './pages/Layout.js';
import { Setup } from './pages/Setup.js';
import { htmlResponse } from '../../html/csp.js';
import { versionedAsset } from '../../html/versionedAsset.js';
import { ZeroRuntime } from '../../html/zeroRuntime.js';

const template = Bun.file('./lib/admin/ui/htmlTemplate.html');

export async function renderAdminShell(props: {
	needsSetup: boolean;
	me: AdminContext | null;
}) {
	let html = await template.text();
	html = html
		.replace('/public/admin.js', versionedAsset('admin.js'))
		.replace('/public/favicon.ico', versionedAsset('favicon.ico'));
	// Hashed for the page's content security policy, so the authorization is derived from the script
	// that is actually served rather than restated beside it.
	const propsScript = `window.PROPS=${JSON.stringify(props).replace(/</g, '\\u003c')}`;
	html = html
		.replace('<!--app-props-->', `<script>${propsScript}</script>`)
		.replace(
			'<!--app-styles-->',
			`<link rel="stylesheet" href="${versionedAsset('reset.css')}" /><link rel="stylesheet" href="${versionedAsset('antd.css')}" />`
		)
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<ZeroRuntime>
						{props.needsSetup ? <Setup /> : <Layout me={props.me} />}
					</ZeroRuntime>
				</StrictMode>
			)
		);
	return htmlResponse(html);
}
