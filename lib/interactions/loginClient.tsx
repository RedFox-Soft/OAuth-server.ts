import { hydrateRoot } from 'react-dom/client';
import React, { StrictMode } from 'react';
import { LoginPage } from './loginPage.tsx';

function calculateUid() {
	const url = new URL(window.location.href);
	const [, uid] = url.pathname.split('/');
	return uid;
}

hydrateRoot(
	// @ts-expect-error root which already exists
	document.getElementById('root'),
	<StrictMode>
		<LoginPage uid={calculateUid()} />
	</StrictMode>
);
