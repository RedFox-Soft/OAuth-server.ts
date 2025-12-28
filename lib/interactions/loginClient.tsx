import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.tsx';
import { ConsentPage } from './consentPage.tsx';

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

hydrateRoot(
	// @ts-expect-error root which already exists
	document.getElementById('root'),
	<StrictMode>
		{pageName() === 'login' ? (
			<LoginPage uid={calculateUid()} />
		) : (
			<ConsentPage
				uid={calculateUid()}
				clientName={''}
				scopes={[]}
			/>
		)}
	</StrictMode>
);
