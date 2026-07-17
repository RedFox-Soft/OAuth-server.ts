import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import type { AdminContext } from '../auth/rbac.js';
import { Layout } from './pages/Layout.tsx';
import { Setup } from './pages/Setup.tsx';

declare global {
	interface Window {
		PROPS?: { needsSetup?: boolean; me?: AdminContext | null };
	}
}

const props = window.PROPS || {};
const me = props.me ?? null;

hydrateRoot(
	document.getElementById('root') as HTMLElement,
	<StrictMode>{props.needsSetup ? <Setup /> : <Layout me={me} />}</StrictMode>
);
