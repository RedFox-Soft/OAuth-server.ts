// Standalone server-rendered pages for the email-verification flow. These are reached
// from a link in an email (possibly a different browser/session), so they are plain,
// self-contained HTML with no dependency on the OIDC interaction cookie or the antd shell.

import { page } from './plainPage.js';
import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import type { Language } from '../i18n/languages.js';
import { html } from '../i18n/message.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';

/*
 * `consoleUrl` is given only for an administrator's address. That is the one case where the server knows
 * where the reader is going next; an end user's application is somewhere this page cannot name, so they
 * are sent back to the sign-in page they came from, which is still open in the tab they signed up in.
 */
export function verifySuccessPage(
	language: Language = 'en',
	consoleUrl?: string
): Response {
	const t = PLAIN_TEXTS[language].verify.success;
	const next = consoleUrl
		? `<a href="${esc(consoleUrl)}" style="display:inline-block; background:${foxVar('primary-solid')}; color:${foxVar('on-primary')}; padding:10px 20px; border-radius:6px; text-decoration:none;">${html(t.console)}</a>`
		: '';
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p>${next}`,
		200,
		{ language }
	);
}

// Failure page for an invalid/expired/used link. Informational — a link click carries no
// bucket context to safely target a resend, so it directs the user back to registration.
export function verifyFailurePage(
	message: string,
	language: Language = 'en'
): Response {
	const t = PLAIN_TEXTS[language].verify.failure;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${esc(message)}</p><p style="color:${foxVar('text-muted')}; font-size:13px;">${html(t.hint)}</p>`,
		400,
		{ language }
	);
}

// 6-digit code entry page (code method). `ref` identifies the challenge; the code is
// never shown here. `error` re-renders after a wrong/expired attempt. Includes a resend
// control that targets this challenge's ref.
export function codeEntryPage(
	ref: string,
	error?: string,
	language: Language = 'en'
): Response {
	const t = PLAIN_TEXTS[language].verify.code;
	const errorHtml = error
		? `<p style="color:${foxVar('danger-text')};">${esc(error)}</p>`
		: '';
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.lead)}</p>${errorHtml}<form method="post" action="/verify-email/code"><input type="hidden" name="ref" value="${esc(ref)}"/><input name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="000000" required style="width:100%; box-sizing:border-box; padding:10px; letter-spacing:6px; text-align:center; font-size:20px; margin-bottom:12px; border:1px solid ${foxVar('field-border')}; border-radius:6px;"/><button type="submit" style="background:${foxVar('primary-solid')}; color:${foxVar('on-primary')}; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; width:100%;">${html(t.submit)}</button></form><form method="post" action="/verify-email/resend" style="margin-top:12px;"><input type="hidden" name="ref" value="${esc(ref)}"/><button type="submit" style="background:none; border:none; color:${foxVar('link')}; cursor:pointer; text-decoration:underline;">${html(t.resend)}</button></form>`,
		200,
		{ language }
	);
}

export function resendAcceptedPage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].verify.resendAccepted;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p>`,
		200,
		{ language }
	);
}

export function verifyRateLimitedPage(
	message: string,
	language: Language = 'en'
): Response {
	const t = PLAIN_TEXTS[language].verify.rateLimited;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${esc(message)}</p>`,
		429,
		{ language }
	);
}
