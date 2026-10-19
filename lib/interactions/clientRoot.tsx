import { StrictMode, type ReactElement } from 'react';
import { LoginPage } from './loginPage.tsx';
import { ConsentPage } from './consentPage.tsx';
import { emptyConsentView } from './consentView.ts';
import { RegistrationPage } from './registration.tsx';
import { TotpPage } from './totpPage.tsx';
import { EndUserTheme } from '../html/theme/provider.tsx';
import type { PaintedAccent } from '../html/theme/accent.ts';
import { isLanguage } from '../i18n/languages.ts';

/*
 * The tree the browser hydrates, apart from the browser: the bundle (loginClient.tsx) reads the page name and
 * uid off the URL and hands them here, and test/dark_theme/hydration.spec.ts renders this same tree against
 * the server's markup. Whatever the server wraps a page in, this must wrap it in too — the theme above all,
 * whose key and tokens decide every class and custom property on the page.
 */
export function clientRoot(
	page: string | undefined,
	uid: string,
	props: object
): ReactElement {
	/*
	 * The server put the page's language and, for an application's own sign-in, its colour in the props
	 * (serverRender.tsx); the colour is the server's decision, handed over already painted (specs/106).
	 */
	const { language, accent } = props as {
		language?: unknown;
		accent?: PaintedAccent;
	};
	return (
		<StrictMode>
			<EndUserTheme
				zeroRuntime
				language={isLanguage(language) ? language : 'en'}
				accent={accent}
			>
				{pageElement(page, uid, props)}
			</EndUserTheme>
		</StrictMode>
	);
}

function pageElement(
	page: string | undefined,
	uid: string,
	props: object
): ReactElement | null {
	switch (page) {
		case 'login':
			return (
				<LoginPage
					uid={uid}
					{...props}
				/>
			);
		case 'consent':
			return (
				<ConsentPage
					{...emptyConsentView(uid)}
					{...props}
				/>
			);
		case 'registration':
			// Spreading props is not parity for its own sake: a message the server rendered into
			// this page is erased the moment React hydrates from props that never carried it, in
			// the browser only and with nothing logged anywhere.
			return (
				<RegistrationPage
					uid={uid}
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
					uid={uid}
					mode="verify"
					{...props}
				/>
			);
		default:
			return null;
	}
}
