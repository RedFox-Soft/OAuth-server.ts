import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.tsx';
import { ConsentPage } from './consentPage.tsx';
import { RegistrationPage } from './registration.tsx';

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

hydrateRoot(
	// @ts-expect-error root which already exists
	document.getElementById('root'),
	<StrictMode>
		{(() => {
			switch (pageName()) {
				case 'login':
					return (
						<LoginPage
							uid={calculateUid()}
							{...props}
						/>
					);
				case 'consent':
					return (
						<ConsentPage
							uid={calculateUid()}
							clientName={''}
							account={undefined}
							permissions={[]}
							{...props}
						/>
					);
				case 'registration':
					// Spreading props is not parity for its own sake: a message the server rendered into
					// this page is erased the moment React hydrates from props that never carried it, in
					// the browser only and with nothing logged anywhere.
					return (
						<RegistrationPage
							uid={calculateUid()}
							{...props}
						/>
					);
			}
		})()}
	</StrictMode>
);
