/*
 * Every page an end user can be shown, through its real renderer, once each. Shared by the CSP walk
 * (test/csp/) and the colour-scheme suite (test/dark_theme/) so the two cannot cover different pages: a page
 * added here is held to both, and a page missing here is held to neither.
 */

import { ISSUER } from 'lib/configs/env.js';
import { getErrorHtmlResponse } from 'lib/html/error.tsx';
import { formPost } from 'lib/html/formPost.tsx';
import { logout } from 'lib/html/logout.tsx';
import { logoutSuccess } from 'lib/html/logoutSuccess.tsx';
import {
	deviceInputPage,
	deviceConfirmPage,
	deviceSuccessPage
} from 'lib/html/device.tsx';
import {
	loginServer,
	registrationServer,
	consentServer,
	totpServer
} from 'lib/interactions/serverRender.tsx';
import { emptyConsentView } from 'lib/interactions/consentView.ts';
import {
	verifySuccessPage,
	verifyFailurePage,
	codeEntryPage,
	resendAcceptedPage,
	verifyRateLimitedPage
} from 'lib/interactions/verifyPages.tsx';
import {
	resetRequestPage,
	resetRequestAcceptedPage,
	resetFormPage,
	resetSuccessPage,
	resetFailurePage
} from 'lib/interactions/resetPages.tsx';
import {
	registrationClosedPage,
	registrationSendFailedPage
} from 'lib/interactions/registrationPages.tsx';
import { confirmationPage as untrustedRedirectPage } from 'lib/interactions/confirmationPage.tsx';
import {
	listPage,
	confirmationPage as removalConfirmationPage,
	outcomePage
} from 'lib/account_page/html.ts';
import type { ApplicationRow } from 'lib/account_page/view.ts';
import {
	federationExpiredPage,
	federationInactivePage,
	federationNoEmailPage,
	federationRejectedPage,
	federationUpstreamPage,
	passwordLoginClosedPage
} from 'lib/federation/pages.tsx';
import type { Language } from 'lib/i18n/languages.ts';
import { renderAdminShell } from 'lib/admin/ui/serverRender.tsx';
import { paintedAccent } from 'lib/html/theme/accent.ts';

export type PageFamily = 'hydrated' | 'terminal' | 'plain';

const nothing = () => ({ items: [], resources: [], rar: [] });

export const APPLICATION_ROW: ApplicationRow = {
	clientId: 'client-1',
	name: 'Acme Notes',
	hosts: ['notes.example.com'],
	moreHosts: 0,
	onDevice: false,
	logo: 'data:image/png;base64,iVBORw0KGgo=',
	trusted: false,
	groups: { see: nothing(), act: nothing(), other: nothing() },
	confirmsIdentity: true,
	givenAt: new Date('2026-10-01T10:00:00Z'),
	lastTokenAt: new Date('2026-10-12T10:00:00Z'),
	keepsAccess: true
};

const frame = (language: Language) => ({
	service: 'Acme ID',
	logoSrc: '/public/logo.svg',
	path: '/account/apps',
	signOutHref: '/session/end',
	email: 'person@example.com',
	language
});

/*
 * Each page takes the language to render in, so a walk can cover every page in every language (specs/097). A
 * renderer called without one renders English, as an existing caller always has.
 */
export const END_USER_PAGES: Array<
	[string, PageFamily, (language?: Language) => Response | Promise<Response>]
> = [
	['sign-in', 'hydrated', (language) => loginServer('uid-1', { language })],
	[
		'sign-in with an error',
		'hydrated',
		(language) =>
			loginServer('uid-1', { errorMessage: 'wrong password', language })
	],
	[
		'sign-in with providers',
		'hydrated',
		(language) =>
			loginServer('uid-1', {
				providers: [
					{ id: 'gh', displayName: 'GitHub', brand: 'github' },
					{ id: 'gg', displayName: 'Google', brand: 'google' }
				],
				language
			})
	],
	[
		'registration',
		'hydrated',
		(language) => registrationServer('uid-1', { language })
	],
	[
		'two-step code',
		'hydrated',
		(language) =>
			totpServer('uid-1', {
				mode: 'verify',
				errorMessage: 'wrong code',
				language
			})
	],
	[
		'two-step enrolment',
		'hydrated',
		(language) =>
			totpServer('uid-1', {
				mode: 'enroll',
				otpauthUri: 'otpauth://totp/x?secret=ABC',
				secretText: 'ABC',
				language
			})
	],
	[
		'consent',
		'hydrated',
		(language) =>
			consentServer(
				{
					...emptyConsentView('uid-1'),
					client: { name: 'Client</script>', tier: 'self-registered' }
				},
				{ language }
			)
	],
	/*
	 * An application's colour adds a style block and a prop to these pages (specs/106), so a coloured page is
	 * held to the same rules as a plain one: one theme head, no colour in a style attribute, no new source in
	 * the content-security policy.
	 */
	[
		'sign-in of an application with a colour',
		'hydrated',
		(language) =>
			loginServer('uid-1', { language, accent: paintedAccent('#2f7d32') })
	],
	[
		'consent of an application with a colour',
		'hydrated',
		(language) =>
			consentServer(
				{
					...emptyConsentView('uid-1'),
					client: { name: 'Timesheets', tier: 'this-organization' }
				},
				{ language, accent: paintedAccent('#2f7d32') }
			)
	],
	[
		'error',
		'terminal',
		(language) =>
			getErrorHtmlResponse(400, 'invalid_request', 'nope', undefined, language)
	],
	[
		'device code entry',
		'terminal',
		(language) =>
			deviceInputPage({
				action: `${ISSUER}/device`,
				secret: 'xsrf',
				charset: 'digits',
				language
			})
	],
	[
		'device confirmation',
		'terminal',
		(language) =>
			deviceConfirmPage({
				action: `${ISSUER}/device`,
				secret: 'xsrf',
				userCode: 'ABC-DEF',
				client: { clientId: 'client' },
				language
			})
	],
	[
		'device success',
		'terminal',
		(language) => deviceSuccessPage({ client: {}, language })
	],
	[
		'logout confirmation',
		'terminal',
		(language) =>
			logout('xsrf', `${ISSUER}/logout/confirm`, undefined, language)
	],
	['logout success', 'terminal', (language) => logoutSuccess(language)],
	[
		'auto-submit callback',
		'terminal',
		(language) =>
			formPost(
				undefined,
				'https://client.example.com/cb',
				{
					code: 'abc',
					state: 'xyz'
				},
				language
			)
	],
	['email verified', 'plain', (language) => verifySuccessPage(language)],
	[
		'verification failed',
		'plain',
		(language) => verifyFailurePage('expired', language)
	],
	[
		'verification code entry',
		'plain',
		(language) => codeEntryPage('ref-1', 'wrong code', language)
	],
	['verification resent', 'plain', (language) => resendAcceptedPage(language)],
	[
		'verification rate limited',
		'plain',
		(language) => verifyRateLimitedPage('slow down', language)
	],
	[
		'reset request',
		'plain',
		(language) => resetRequestPage('uid-1', 'bad address', language)
	],
	[
		'reset requested',
		'plain',
		(language) => resetRequestAcceptedPage(language)
	],
	[
		'reset form',
		'plain',
		(language) =>
			resetFormPage(
				'token',
				{ purpose: 'reset', bucketName: 'Acme' },
				'too short',
				language
			)
	],
	[
		'invitation form',
		'plain',
		(language) =>
			resetFormPage(
				'token',
				{ purpose: 'invite', bucketName: 'Acme' },
				undefined,
				language
			)
	],
	['reset done', 'plain', (language) => resetSuccessPage('reset', language)],
	[
		'invitation done',
		'plain',
		(language) => resetSuccessPage('invite', language)
	],
	['reset failed', 'plain', (language) => resetFailurePage(language)],
	[
		'registration closed',
		'plain',
		(language) => registrationClosedPage(language)
	],
	[
		'registration email failed',
		'plain',
		(language) => registrationSendFailedPage(language)
	],
	[
		'connected applications',
		'plain',
		(language = 'en') =>
			listPage(frame(language), [APPLICATION_ROW], 'Access removed.')
	],
	[
		'connected application removal',
		'plain',
		(language = 'en') =>
			removalConfirmationPage(frame(language), APPLICATION_ROW, 'xsrf')
	],
	[
		'connected applications outcome',
		'plain',
		(language = 'en') => outcomePage('expired', '/account/apps', 400, language)
	],
	[
		'untrusted redirect',
		'plain',
		(language) =>
			untrustedRedirectPage({
				answer: {
					method: 'GET',
					url: 'https://elsewhere.example/cb?error=access_denied'
				},
				error: 'access_denied',
				redirectUri: 'https://elsewhere.example/cb',
				language
			})
	],
	[
		'federation refused',
		'plain',
		(language) => federationRejectedPage('uid-1', language)
	],
	[
		'federation expired',
		'plain',
		(language) => federationExpiredPage(language)
	],
	[
		'federation upstream',
		'plain',
		(language) => federationUpstreamPage(language)
	],
	[
		'federation no email',
		'plain',
		(language) => federationNoEmailPage(language)
	],
	[
		'federation inactive',
		'plain',
		(language) => federationInactivePage(language)
	],
	[
		'password sign-in closed',
		'plain',
		(language) => passwordLoginClosedPage('uid-1', language)
	]
];

export const ADMIN_SHELL = (): Promise<Response> | Response =>
	renderAdminShell({ needsSetup: true, me: null });
