import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import type { AdminMeView } from '../me_view.js';
import type { MeCan } from '../auth/can.js';
import { ConsoleRoot } from './frame/ConsoleRoot.js';
import { htmlResponse } from '../../html/csp.js';
import { versionedAsset } from '../../html/versionedAsset.js';

const template = Bun.file('./lib/admin/ui/htmlTemplate.html');

/* What the shell writes to `window.PROPS`, and so what adminClient.tsx reads back. */
export interface AdminShellProps {
	needsSetup: boolean;
	/*
	 * With `can`, so the first render offers what the server will accept: the address forms a team may choose
	 * depend on a live setting (specs/101), and no fallback in the browser can guess them.
	 */
	me: (AdminMeView & { can?: MeCan }) | null;
	/* The address asked for, path and query: the router's first render, on both sides. */
	path?: string;
	/*
	 * ISSUER's host, port included, so the console can show a subdomain project's address
	 * (`<slug>.<instanceHost>`, specs/101). Passed rather than imported: the browser bundle never reads the
	 * environment.
	 */
	instanceHost?: string;
}

export async function renderAdminShell(props: AdminShellProps, status = 200) {
	let html = await template.text();
	html = html
		.replace('/public/admin.js', versionedAsset('admin.js'))
		.replace('/public/favicon.ico', versionedAsset('favicon.ico'));
	// Hashed for the page's content security policy, so the authorization is derived from the script
	// that is actually served rather than restated beside it.
	const propsScript = `window.PROPS=${JSON.stringify(props).replace(/</g, '\\u003c')}`;
	const styles = `<link rel="stylesheet" href="${versionedAsset('reset.css')}" /><link rel="stylesheet" href="${versionedAsset('antd.css')}" />`;
	const body = renderToString(
		<StrictMode>
			<ConsoleRoot {...props} />
		</StrictMode>
	);
	/*
	 * Function replacements, as lib/interactions/serverRender.tsx uses: a string replacement expands `$'`, `` $` ``
	 * and `$&`, and the props carry the page's own address, so a link to `/admin/x$'` spliced the rest of the
	 * template into the script and the console never loaded (specs/103).
	 */
	html = html
		.replace('<!--app-props-->', () => `<script>${propsScript}</script>`)
		.replace('<!--app-styles-->', () => styles)
		.replace('<!--app-html-->', () => body);
	return htmlResponse(html, { status });
}
