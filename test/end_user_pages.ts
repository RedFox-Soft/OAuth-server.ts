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
	federationRejectedPage,
	passwordLoginClosedPage
} from 'lib/federation/pages.tsx';
import { renderAdminShell } from 'lib/admin/ui/serverRender.tsx';

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

const FRAME = {
	service: 'Acme ID',
	logoSrc: '/public/logo.svg',
	path: '/account/apps',
	signOutHref: '/session/end',
	email: 'person@example.com'
};

export const END_USER_PAGES: Array<
	[string, PageFamily, () => Response | Promise<Response>]
> = [
	['sign-in', 'hydrated', () => loginServer('uid-1')],
	[
		'sign-in with an error',
		'hydrated',
		() => loginServer('uid-1', { errorMessage: 'wrong password' })
	],
	[
		'sign-in with providers',
		'hydrated',
		() =>
			loginServer('uid-1', {
				providers: [
					{ id: 'gh', displayName: 'GitHub', brand: 'github' },
					{ id: 'gg', displayName: 'Google', brand: 'google' }
				]
			})
	],
	['registration', 'hydrated', () => registrationServer('uid-1')],
	[
		'two-step code',
		'hydrated',
		() => totpServer('uid-1', { mode: 'verify', errorMessage: 'wrong code' })
	],
	[
		'two-step enrolment',
		'hydrated',
		() =>
			totpServer('uid-1', {
				mode: 'enroll',
				otpauthUri: 'otpauth://totp/x?secret=ABC',
				secretText: 'ABC'
			})
	],
	[
		'consent',
		'hydrated',
		() =>
			consentServer({
				...emptyConsentView('uid-1'),
				client: { name: 'Client</script>', tier: 'self-registered' }
			})
	],
	[
		'error',
		'terminal',
		() => getErrorHtmlResponse(400, 'invalid_request', 'nope')
	],
	[
		'device code entry',
		'terminal',
		() =>
			deviceInputPage({
				action: `${ISSUER}/device`,
				secret: 'xsrf',
				charset: 'digits'
			})
	],
	[
		'device confirmation',
		'terminal',
		() =>
			deviceConfirmPage({
				action: `${ISSUER}/device`,
				secret: 'xsrf',
				userCode: 'ABC-DEF',
				client: { clientId: 'client' }
			})
	],
	['device success', 'terminal', () => deviceSuccessPage({ client: {} })],
	[
		'logout confirmation',
		'terminal',
		() => logout('xsrf', `${ISSUER}/logout/confirm`)
	],
	['logout success', 'terminal', () => logoutSuccess()],
	[
		'auto-submit callback',
		'terminal',
		() =>
			formPost({}, 'https://client.example.com/cb', {
				code: 'abc',
				state: 'xyz'
			})
	],
	['email verified', 'plain', () => verifySuccessPage()],
	['verification failed', 'plain', () => verifyFailurePage('expired')],
	[
		'verification code entry',
		'plain',
		() => codeEntryPage('ref-1', 'wrong code')
	],
	['verification resent', 'plain', () => resendAcceptedPage()],
	[
		'verification rate limited',
		'plain',
		() => verifyRateLimitedPage('slow down')
	],
	['reset request', 'plain', () => resetRequestPage('uid-1', 'bad address')],
	['reset requested', 'plain', () => resetRequestAcceptedPage()],
	[
		'reset form',
		'plain',
		() =>
			resetFormPage(
				'token',
				{ purpose: 'reset', bucketName: 'Acme' },
				'too short'
			)
	],
	['reset done', 'plain', () => resetSuccessPage('reset')],
	['reset failed', 'plain', () => resetFailurePage()],
	['registration closed', 'plain', () => registrationClosedPage()],
	['registration email failed', 'plain', () => registrationSendFailedPage()],
	[
		'connected applications',
		'plain',
		() => listPage(FRAME, [APPLICATION_ROW], 'Access removed.')
	],
	[
		'connected application removal',
		'plain',
		() => removalConfirmationPage(FRAME, APPLICATION_ROW, 'xsrf')
	],
	[
		'connected applications outcome',
		'plain',
		() => outcomePage('Sign-in expired', 'Try again.', '/account/apps', 400)
	],
	[
		'untrusted redirect',
		'plain',
		() =>
			untrustedRedirectPage({
				answer: {
					method: 'GET',
					url: 'https://elsewhere.example/cb?error=access_denied'
				},
				error: 'access_denied',
				redirectUri: 'https://elsewhere.example/cb'
			})
	],
	['federation refused', 'plain', () => federationRejectedPage('uid-1')],
	['password sign-in closed', 'plain', () => passwordLoginClosedPage('uid-1')]
];

export const ADMIN_SHELL = (): Promise<Response> | Response =>
	renderAdminShell({ needsSetup: true, me: null });
