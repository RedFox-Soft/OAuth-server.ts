import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import type { AdminContext } from '../auth/rbac.js';
import { Layout } from './pages/Layout.tsx';
import { Setup } from './pages/Setup.tsx';
import { ZeroRuntime } from '../../html/zeroRuntime.js';

declare global {
	interface Window {
		PROPS?: { needsSetup?: boolean; me?: AdminContext | null };
	}
}

const props = window.PROPS || {};
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
