import { hydrateRoot } from 'react-dom/client';
import { clientRoot } from './clientRoot.tsx';

declare global {
	interface Window {
		PROPS?: unknown;
	}
}

function calculateUid() {
	const url = new URL(window.location.href);
	const [, , uid] = url.pathname.split('/');
	return uid;
}

function pageName() {
	const url = new URL(window.location.href);
	const [, , , name] = url.pathname.split('/');
	return name;
}

const props = window.PROPS || {};

// The template renders this; if it is missing, the document is not the one this bundle is for, and
// saying so beats failing somewhere inside React.
const root = document.getElementById('root');
if (!root) {
	throw new Error('#root is missing from the document');
}

hydrateRoot(root, clientRoot(pageName(), calculateUid(), props));
