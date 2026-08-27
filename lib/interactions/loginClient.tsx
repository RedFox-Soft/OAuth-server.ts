import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.tsx';
import { ConsentPage } from './consentPage.tsx';
import { RegistrationPage } from './registration.tsx';
import { TotpPage } from './totpPage.tsx';
import { ZeroRuntime } from '../html/zeroRuntime.js';

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

hydrateRoot(
	root,
	<StrictMode>
		<ZeroRuntime>
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
					case 'totp':
						/*
						 * Both `ui/:uid/totp` and `ui/:uid/totp/enroll` land here — the page name is the
						 * fourth path segment, which is `totp` for both — so which of the two this is comes
						 * from the props, never from the URL.
						 *
						 * `mode` is defaulted to the code page and the spread comes last, so the server's
						 * value wins. Drop the spread and the enrolment page hydrates into the code page:
						 * the QR and the secret disappear the instant React takes over, leaving a form that
						 * asks for a code from an authenticator the person was never able to set up.
						 */
						return (
							<TotpPage
								uid={calculateUid()}
								mode="verify"
								{...props}
							/>
						);
				}
			})()}
		</ZeroRuntime>
	</StrictMode>
);
