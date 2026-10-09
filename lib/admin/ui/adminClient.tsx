import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import { message } from 'antd';
import type { AdminShellProps } from './serverRender.tsx';
import { Layout } from './pages/Layout.tsx';
import { Setup } from './pages/Setup.tsx';
import { ZeroRuntime } from '../../html/zeroRuntime.js';

/*
 * `unknown` here as in loginClient.tsx: both augment the one global `Window`, and two different types
 * for the property are a compile error once both bundles are checked together. The shape is stated at
 * the read instead, from the type the server renders it with.
 */
declare global {
	interface Window {
		PROPS?: unknown;
	}
}

/*
 * Every button, form and confirmation in the console runs an async handler that checks the response it
 * gets. What a handler cannot check is a request that got none — the network gone, the server down —
 * which rejects, and nothing awaits a click: the rejection reached only the browser console while the
 * page looked idle. Reported here once, for every handler, which is why the lint does not ask each JSX
 * attribute to handle its own (`checksVoidReturn.attributes` in eslint.config.ts). The browser still
 * logs the reason; the administrator is told only that the action did not complete.
 */
window.addEventListener('unhandledrejection', () => {
	void message.error(
		'That action did not complete. Check the connection to the server and try again.'
	);
});

const props = (window.PROPS ?? {}) as Partial<AdminShellProps>;
const me = props.me ?? null;

// The template renders this; if it is missing, the document is not the one this bundle is for, and
// saying so beats failing somewhere inside React.
const root = document.getElementById('root');
if (!root) {
	throw new Error('#root is missing from the document');
}

hydrateRoot(
	root,
	<StrictMode>
		<ZeroRuntime>
			{props.needsSetup ? <Setup /> : <Layout me={me} />}
		</ZeroRuntime>
	</StrictMode>
);
