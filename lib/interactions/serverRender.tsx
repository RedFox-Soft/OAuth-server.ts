import { renderToString } from 'react-dom/server';
import { StrictMode, type ReactElement } from 'react';
import { LoginPage } from './loginPage.js';
import { ConsentPage } from './consentPage.js';
import { RegistrationPage } from './registration.js';
import { TotpPage } from './totpPage.js';
import type { ConsentView } from './consentView.js';
import type { SwitcherProps } from './languageSwitch.js';
import type { OfferedProvider } from './signInOptions.js';
import type { Language } from '../i18n/languages.js';
import { CONSENT_TEXTS } from '../i18n/texts/consent/index.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import { htmlResponse } from '../html/csp.js';
import { versionedAsset } from '../html/versionedAsset.js';
import { renderEndUserTree } from '../html/theme/dark.js';
import { accentStyle, type PaintedAccent } from '../html/theme/accent.js';

const htmlTeamplate = Bun.file('./lib/interactions/htmlTeamplate.html');

// escape `<` so a client name / scope value can't break out of the script tag
function propsScript(props: unknown): string {
	return `<script>window.PROPS=${JSON.stringify(props).replace(/</g, '\\u003c')}</script>`;
}

/*
 * reset before components, so antd's reset does not override component styles.
 */
function styleLinks(): string {
	return [
		`<link rel="stylesheet" href="${versionedAsset('reset.css')}" />`,
		`<link rel="stylesheet" href="${versionedAsset('antd.css')}" />`
	].join('');
}

/*
 * A hydrated page's markup and the <head> it needs (specs/096): the compiled stylesheets, then the theme, the
 * page's own antd custom properties and their dark counterparts. The tree is the one lib/interactions/
 * clientRoot.tsx hydrates — StrictMode outside, the end-user theme inside — so the two cannot disagree.
 * The replacements are functions because a replacement string reads `$&` and its kin as patterns.
 */
function hydratedPage(
	template: string,
	title: string,
	props: object,
	page: ReactElement,
	language: Language,
	accent: PaintedAccent | undefined
): string {
	const tree = renderEndUserTree(page, {
		zeroRuntime: true,
		language,
		accent,
		render: (element) => renderToString(<StrictMode>{element}</StrictMode>)
	});
	/*
	 * The language travels in the props as well as in the markup: the browser rebuilds the tree from the props,
	 * and a client that defaulted to English would rewrite a Russian page on load (specs/097). An application's
	 * colour travels the same way (specs/106): the markup is identical without it — antd's class hash ignores
	 * token values — but on hydration cssinjs writes its own light custom properties, which would put the
	 * default blue back after load, in the browser only and with nothing logged.
	 */
	return template
		.replace('__APP_LANG__', language)
		.replace('/public/loginClient.js', versionedAsset('loginClient.js'))
		.replace('/public/favicon.ico', versionedAsset('favicon.ico'))
		.replace('<!--app-title-->', () => title)
		.replace(
			'<!--app-styles-->',
			() => styleLinks() + tree.head + (accent ? accentStyle(accent) : '')
		)
		.replace('<!--app-props-->', () =>
			propsScript({ ...props, language, ...(accent ? { accent } : {}) })
		)
		.replace('<!--app-html-->', () => tree.html);
}

export async function loginServer(
	uid: string,
	options: {
		errorMessage?: string;
		notice?: string;
		/*
		 * What this bucket offers. Both default to the password-only page a caller that knows nothing about
		 * federation would expect, so an omitted option cannot silently strip a working sign-in form — the
		 * failure mode a required parameter would have introduced across every existing call site.
		 */
		passwordLogin?: boolean;
		registrationOpen?: boolean;
		passwordReset?: boolean;
		/*
		 * Offers "send the link again" — only on a page the server rendered after proving the password of
		 * an unverified account, never from anything in the request.
		 */
		verificationResend?: boolean;
		providers?: OfferedProvider[];
		/* "More sign-in options" starts open — after a cancelled provider sign-in (specs/105). */
		providersOpen?: boolean;
		/*
		 * The pending authorization request's redirect_uri, which reaches this page's
		 * Content-Security-Policy. `form-action` has to name it: the page posts to itself, and the
		 * response to that post redirects to the client — a hop the browser checks against the policy of
		 * the document the form was submitted from.
		 */
		handOffTo?: string;
		language?: Language;
		switcher?: SwitcherProps;
		accent?: PaintedAccent;
	} = {}
) {
	const { errorMessage, switcher } = options;
	const language = options.language ?? 'en';
	// Exclusivity is a property of this function rather than a promise made at each call site: a rejected
	// submission must never be accompanied by the notice the page was reached with.
	const notice = errorMessage ? undefined : options.notice;
	const passwordLogin = options.passwordLogin !== false;
	const registrationOpen = options.registrationOpen !== false;
	const passwordReset = options.passwordReset !== false;
	const verificationResend = options.verificationResend === true;
	const providers = options.providers ?? [];
	const providersOpen = options.providersOpen === true;

	// Here and nowhere else: the version is the file's build time, which only the server can read (see LoginPage).
	const logoSrc = versionedAsset('logo.svg');
	/*
	 * The props are half of this change, not a detail of it. This page hydrates, so React rebuilds the
	 * tree from `window.PROPS` — provider buttons rendered here but absent there vanish in a browser,
	 * silently, with nothing logged and no server-side test able to see it. That is exactly how the
	 * registration page's missing props survived from its introduction until spec 021.
	 */
	const html = hydratedPage(
		await htmlTeamplate.text(),
		SIGN_IN_TEXTS[language].titles.login,
		{
			uid,
			errorMessage,
			notice,
			passwordLogin,
			registrationOpen,
			passwordReset,
			verificationResend,
			providers,
			providersOpen,
			logoSrc,
			switcher
		},
		<LoginPage
			uid={uid}
			errorMessage={errorMessage}
			notice={notice}
			passwordLogin={passwordLogin}
			registrationOpen={registrationOpen}
			passwordReset={passwordReset}
			verificationResend={verificationResend}
			providers={providers}
			providersOpen={providersOpen}
			logoSrc={logoSrc}
			switcher={switcher}
		/>,
		language,
		options.accent
	);
	// A notice is not a failure: only the error re-render answers 400.
	return htmlResponse(html, {
		status: errorMessage ? 400 : 200,
		handOffTo: options.handOffTo,
		language
	});
}

export async function registrationServer(
	uid: string,
	options: {
		errorMessage?: string;
		email?: string;
		handOffTo?: string;
		language?: Language;
		switcher?: SwitcherProps;
		accent?: PaintedAccent;
	} = {}
) {
	const { errorMessage, email, switcher } = options;
	const language = options.language ?? 'en';

	// Here and nowhere else: the version is the file's build time, which only the server can read (see LoginPage).
	const logoSrc = versionedAsset('logo.svg');
	// The props are what the hydrated tree is built from: without them React replaces the
	// server-rendered page with one that never heard about the error, silently and in the browser
	// only.
	const html = hydratedPage(
		await htmlTeamplate.text(),
		SIGN_IN_TEXTS[language].titles.registration,
		{ uid, errorMessage, email, logoSrc, switcher },
		<RegistrationPage
			uid={uid}
			errorMessage={errorMessage}
			email={email}
			logoSrc={logoSrc}
			switcher={switcher}
		/>,
		language,
		options.accent
	);
	// Neither submitted password reaches this document — not the markup, not the props (spec FR-011).
	return htmlResponse(html, {
		status: errorMessage ? 400 : 200,
		handOffTo: options.handOffTo,
		language
	});
}

export async function totpServer(
	uid: string,
	options: {
		mode: 'verify' | 'enroll';
		errorMessage?: string;
		otpauthUri?: string;
		secretText?: string;
		handOffTo?: string;
		language?: Language;
		switcher?: SwitcherProps;
		accent?: PaintedAccent;
	}
) {
	const { mode, errorMessage, otpauthUri, secretText, switcher } = options;
	const language = options.language ?? 'en';
	const T = SIGN_IN_TEXTS[language];

	// Here and nowhere else: the version is the file's build time, which only the server can read (see LoginPage).
	const logoSrc = versionedAsset('logo.svg');
	/*
	 * `mode` must be in the props as well as in the render. It decides whether the page shows a QR at all,
	 * so a props script that omitted it would hydrate the enrolment page into the code page — the QR and
	 * the secret vanishing the moment React takes over, in a browser only, with nothing logged.
	 */
	const html = hydratedPage(
		await htmlTeamplate.text(),
		mode === 'enroll' ? T.titles.totpEnroll : T.titles.totpVerify,
		{ uid, mode, errorMessage, otpauthUri, secretText, logoSrc, switcher },
		<TotpPage
			uid={uid}
			mode={mode}
			errorMessage={errorMessage}
			otpauthUri={otpauthUri}
			secretText={secretText}
			logoSrc={logoSrc}
			switcher={switcher}
		/>,
		language,
		options.accent
	);
	/*
	 * The submitted code never comes back with the page, in the markup or the props — the same rule the
	 * registration page follows for a password. The enrolment secret does reach the document, which is
	 * unavoidable: enrolment is the act of showing it. It goes no further, and `Cache-Control: no-store`
	 * on every response is what keeps it from being written down on the way.
	 */
	return htmlResponse(html, {
		status: errorMessage ? 400 : 200,
		handOffTo: options.handOffTo,
		language
	});
}

export async function consentServer(
	view: ConsentView,
	options: {
		handOffTo?: string;
		language?: Language;
		switcher?: SwitcherProps;
		accent?: PaintedAccent;
	} = {}
) {
	const language = options.language ?? 'en';
	const { switcher } = options;
	const html = hydratedPage(
		await htmlTeamplate.text(),
		CONSENT_TEXTS[language].pageTitle,
		{ ...view, switcher },
		<ConsentPage
			{...view}
			switcher={switcher}
		/>,
		language,
		options.accent
	);
	return htmlResponse(html, { handOffTo: options.handOffTo, language });
}
