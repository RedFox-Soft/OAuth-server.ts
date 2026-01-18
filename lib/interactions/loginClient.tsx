import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.tsx';
import { ConsentPage } from './consentPage.tsx';
import { RegistrationPage } from './registration.tsx';

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
		{(() => {
			console.log(pageName());
			switch (pageName()) {
				case 'login':
					return <LoginPage uid={calculateUid()} />;
				case 'consent':
					return (
						<ConsentPage
							uid={calculateUid()}
							clientName={''}
							scopes={[]}
						/>
					);
				case 'registration':
					return <RegistrationPage uid={calculateUid()} />;
			}
		})()}
	</StrictMode>
);
