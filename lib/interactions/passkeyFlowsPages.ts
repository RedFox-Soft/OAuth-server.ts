import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import type { Language } from '../i18n/languages.js';
import { html, text } from '../i18n/message.js';
import { ACCOUNT_TEXTS } from '../i18n/texts/account/index.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import { page } from './plainPage.js';

/*
 * Plain-HTML pages for passkey-only registration and self-service passkey recovery (specs/145). Uses the same
 * script-free form shell as `resetPages.tsx` / `verifyPages.tsx` and loads `passkeyButton.js` only on the WebAuthn
 * creation step, keeping CSP strict and avoiding any React hydration mismatch.
 */

const MUTED = `color:${foxVar('text-secondary')};`;
const LINK = `color:${foxVar('link')}; display:inline-block; min-height:24px; line-height:24px;`;
const PRIMARY = `background:${foxVar('primary-solid')}; color:${foxVar('on-primary')}; border:0; border-radius:6px; padding:0 16px; min-height:36px; font-size:14px; cursor:pointer; width:100%;`;
const INPUT = `font-size:16px; min-height:36px; padding:0 10px; border:1px solid ${foxVar('field-border')}; border-radius:6px; width:100%; box-sizing:border-box; margin:6px 0 12px;`;
const ERROR_BOX = `background:${foxVar('danger-bg')}; border:1px solid ${foxVar('danger-border')}; color:${foxVar('danger-text')}; border-radius:6px; padding:8px 12px; margin:12px 0;`;

function errorBanner(message: string | undefined): string {
	return message
		? `<p role="alert" style="${ERROR_BOX}">${esc(message)}</p>`
		: '';
}

function backLink(href: string, label: string): string {
	return `<p style="margin:16px 0 0; text-align:center;"><a href="${esc(href)}" style="${LINK}">${esc(label)}</a></p>`;
}

export function passkeyRegisterEmailPage(input: {
	language: Language;
	service: string;
	action: string;
	loginHref: string;
	passwordHref?: string;
	email?: string;
	error?: string;
	unavailable?: boolean;
	status?: number;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const heading = html(T.heading, { service: input.service });
	const body = input.unavailable
		? `<h1 style="font-size:20px; margin:0 0 8px;">${heading}</h1><p>${esc(T.unavailable)}</p>${backLink(input.loginHref, T.backToSignIn)}`
		: [
				`<h1 style="font-size:20px; margin:0 0 8px;">${heading}</h1>`,
				errorBanner(input.error),
				`<form method="post" action="${esc(input.action)}">`,
				`<label for="pk-reg-email" style="display:block;">${esc(T.emailLabel)}</label>`,
				`<input id="pk-reg-email" name="email" type="email" autocomplete="email" required value="${esc(input.email ?? '')}" style="${INPUT}"/>`,
				`<button type="submit" style="${PRIMARY}">${esc(T.continueButton)}</button>`,
				`</form>`,
				input.passwordHref
					? `<p style="margin:12px 0 0; text-align:center;"><a href="${esc(input.passwordHref)}" style="${LINK}">${esc(T.passwordInstead)}</a></p>`
					: '',
				backLink(input.loginHref, T.backToSignIn)
			].join('');
	const res = page(T.title, body, input.status ?? (input.error ? 400 : 200), {
		language: input.language
	});
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRegisterSentPage(input: {
	language: Language;
	email: string;
	loginHref: string;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.sentHeading)}</h1>`,
		`<p>${html(T.sentLink, { email: input.email })}</p>`,
		backLink(input.loginHref, T.backToSignIn)
	].join('');
	const res = page(T.sentHeading, body, 200, { language: input.language });
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRegisterCodePage(input: {
	language: Language;
	email: string;
	action: string;
	loginHref: string;
	error?: string;
	status?: number;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.sentHeading)}</h1>`,
		`<p>${html(T.sentCode, { email: input.email })}</p>`,
		errorBanner(input.error),
		`<form method="post" action="${esc(input.action)}">`,
		`<label for="pk-reg-code" style="display:block;">${esc(T.codeLabel)}</label>`,
		`<input id="pk-reg-code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required style="${INPUT}"/>`,
		`<button type="submit" style="${PRIMARY}">${esc(T.codeVerify)}</button>`,
		`</form>`,
		backLink(input.loginHref, T.backToSignIn)
	].join('');
	const res = page(T.title, body, input.status ?? (input.error ? 400 : 200), {
		language: input.language
	});
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRegisterCreatePage(input: {
	language: Language;
	email: string;
	action: string;
	options: string;
	script: string;
	loginHref: string;
	passwordHref?: string;
	error?: string;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const A = ACCOUNT_TEXTS[input.language];
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.createHeading)}</h1>`,
		`<p>${html(T.createHint, { email: input.email })}</p>`,
		errorBanner(input.error),
		`<form method="post" action="${esc(input.action)}" data-passkey-add data-options="${esc(input.options)}" data-text-exists="${esc(A.passkeyExists)}" data-text-failed="${esc(A.passkeyAddFailed)}" data-text-no-uv="${esc(A.passkeyNoUserVerification)}" data-text-unsupported="${esc(T.unsupported)}" style="margin-top:12px;">`,
		`<input type="hidden" name="credential" value=""/>`,
		`<button type="button" disabled style="${PRIMARY}">${esc(T.createButton)}</button>`,
		`<p data-passkey-status role="status" style="${MUTED}">${esc(A.passkeyNeedsScript)}</p>`,
		`</form>`,
		`<script src="${esc(input.script)}"></script>`,
		input.passwordHref
			? `<p style="margin:12px 0 0; text-align:center;"><a href="${esc(input.passwordHref)}" style="${LINK}">${esc(T.passwordInstead)}</a></p>`
			: '',
		backLink(input.loginHref, T.backToSignIn)
	].join('');
	const res = page(T.createHeading, body, input.error ? 400 : 200, {
		language: input.language
	});
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRegisterErrorPage(input: {
	language: Language;
	message: string;
	loginHref: string;
	status?: number;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const res = page(
		T.title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.title)}</h1><p>${esc(input.message)}</p>${backLink(input.loginHref, T.backToSignIn)}`,
		input.status ?? 400,
		{ language: input.language }
	);
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRecoveryRequestPage(input: {
	language: Language;
	action: string;
	loginHref: string;
	email?: string;
	error?: string;
	status?: number;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRecovery;
	const TR = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.heading)}</h1>`,
		`<p>${esc(T.intro)}</p>`,
		errorBanner(input.error),
		`<form method="post" action="${esc(input.action)}">`,
		`<label for="pk-rec-email" style="display:block;">${esc(TR.emailLabel)}</label>`,
		`<input id="pk-rec-email" name="email" type="email" autocomplete="email" required value="${esc(input.email ?? '')}" style="${INPUT}"/>`,
		`<button type="submit" style="${PRIMARY}">${esc(T.submit)}</button>`,
		`</form>`,
		backLink(input.loginHref, TR.backToSignIn)
	].join('');
	const res = page(T.title, body, input.status ?? (input.error ? 400 : 200), {
		language: input.language
	});
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRecoverySentPage(input: {
	language: Language;
	email: string;
	loginHref: string;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRecovery;
	const TR = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.sentHeading)}</h1>`,
		`<p>${html(T.sentHint, { email: input.email })}</p>`,
		backLink(input.loginHref, TR.backToSignIn)
	].join('');
	const res = page(T.sentHeading, body, 200, { language: input.language });
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRecoveryInvalidPage(input: {
	language: Language;
	loginHref: string;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRecovery;
	const TR = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const res = page(
		T.title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.title)}</h1><p>${esc(T.invalidLink)}</p>${backLink(input.loginHref, TR.backToSignIn)}`,
		400,
		{ language: input.language }
	);
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRecoveryTotpPage(input: {
	language: Language;
	action: string;
	loginHref: string;
	error?: string;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRecovery;
	const TR = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const A = ACCOUNT_TEXTS[input.language];
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.totpHeading)}</h1>`,
		`<p>${esc(T.totpHint)}</p>`,
		errorBanner(input.error),
		`<form method="post" action="${esc(input.action)}">`,
		`<label for="pk-rec-totp" style="display:block;">${esc(A.passkeySetupTotpLabel)}</label>`,
		`<input id="pk-rec-totp" name="code" inputmode="numeric" autocomplete="one-time-code" required style="${INPUT}"/>`,
		`<button type="submit" style="${PRIMARY}">${esc(T.totpButton)}</button>`,
		`</form>`,
		`<p style="${MUTED} margin-top:12px;">${esc(T.totpLost)}</p>`,
		backLink(input.loginHref, TR.backToSignIn)
	].join('');
	const res = page(T.totpHeading, body, input.error ? 400 : 200, {
		language: input.language
	});
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRecoveryCreatePage(input: {
	language: Language;
	email: string;
	action: string;
	options: string;
	script: string;
	loginHref: string;
	error?: string;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRecovery;
	const TR = SIGN_IN_TEXTS[input.language].passkeyRegister;
	const A = ACCOUNT_TEXTS[input.language];
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.createHeading)}</h1>`,
		`<p>${html(T.createHint, { email: input.email })}</p>`,
		errorBanner(input.error),
		`<form method="post" action="${esc(input.action)}" data-passkey-add data-options="${esc(input.options)}" data-text-exists="${esc(A.passkeyExists)}" data-text-failed="${esc(A.passkeyAddFailed)}" data-text-no-uv="${esc(A.passkeyNoUserVerification)}" style="margin-top:12px;">`,
		`<input type="hidden" name="credential" value=""/>`,
		`<button type="button" disabled style="${PRIMARY}">${esc(T.createButton)}</button>`,
		`<p data-passkey-status role="status" style="${MUTED}">${esc(A.passkeyNeedsScript)}</p>`,
		`</form>`,
		`<script src="${esc(input.script)}"></script>`,
		backLink(input.loginHref, TR.backToSignIn)
	].join('');
	const res = page(T.createHeading, body, input.error ? 400 : 200, {
		language: input.language
	});
	res.headers.set('cache-control', 'no-store');
	return res;
}

export function passkeyRecoveryDonePage(input: {
	language: Language;
	loginHref: string;
}): Response {
	const T = SIGN_IN_TEXTS[input.language].passkeyRecovery;
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.doneHeading)}</h1>`,
		`<p>${esc(T.doneHint)}</p>`,
		`<p style="margin:16px 0 0;"><a href="${esc(input.loginHref)}" style="display:inline-block; text-align:center; text-decoration:none; ${PRIMARY} line-height:36px;">${esc(T.signInButton)}</a></p>`
	].join('');
	const res = page(text(T.doneHeading), body, 200, {
		language: input.language
	});
	res.headers.set('cache-control', 'no-store');
	return res;
}
