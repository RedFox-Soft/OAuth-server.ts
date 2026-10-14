// Standalone server-rendered pages for the self-service password reset. Three of the four screens are
// reached from a link in an email (often a different browser, always without the interaction cookie), so
// the whole family is plain, self-contained HTML with no dependency on the OIDC interaction cookie or the
// antd shell — the same reasoning verifyPages.tsx records, and the reason the request form joins them
// rather than matching the login page it is reached from.

import { page } from './plainPage.js';
import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import type { SetPasswordPurpose } from '../password_reset/types.js';
import type { Language } from '../i18n/languages.js';
import { html, text } from '../i18n/message.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';
import { languageSwitchHtml, type SwitcherProps } from './languageSwitch.js';

/*
 * What the page knows about the link it was opened from (specs/089). A reset and an administrator's invitation
 * share the secret and the form; only the words differ, and only once the link has been found valid — an
 * invalid link has no purpose to show, which is why the failure page below speaks for both.
 */
export interface SetPasswordContext {
	purpose: SetPasswordPurpose;
	bucketName: string;
}

const input = `width:100%; box-sizing:border-box; padding:10px; margin-bottom:12px; border:1px solid ${foxVar('field-border')}; border-radius:6px;`;
const button = `background:${foxVar('primary-solid')}; color:${foxVar('on-primary')}; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; width:100%;`;

function errorHtml(error?: string): string {
	return error
		? `<p style="color:${foxVar('danger-text')};">${esc(error)}</p>`
		: '';
}

// Where a locked-out user starts. Inside the interaction (the form posts back to `ui/:uid`), because the
// bucket an address is looked up in has to come from the client that began the authorization request.
export function resetRequestPage(
	uid: string,
	error?: string,
	language: Language = 'en',
	switcher?: SwitcherProps
): Response {
	const t = PLAIN_TEXTS[language].reset.request;
	const switchHtml = switcher ? languageSwitchHtml(switcher, language) : '';
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.lead)}</p>${errorHtml(error)}<form method="post" action="/ui/${esc(uid)}/forgot-password"><input name="email" type="email" autocomplete="email" placeholder="${html(t.emailPlaceholder)}" required style="${input}"/><button type="submit" style="${button}">${html(t.submit)}</button></form><p style="margin-top:12px;"><a href="/ui/${esc(uid)}/login" style="color:${foxVar('link')};">${html(t.back)}</a></p>${switchHtml}`,
		200,
		{ language }
	);
}

/*
 * The one answer every request gets: registered, unregistered, another bucket's address, a deactivated
 * account, the reserved admin bucket, a send that failed, or one the cooldown or daily cap held back —
 * that last because the throttle exists only for addresses with an account. A constant with nothing
 * interpolated, so "byte-identical across outcomes" is a property of this function rather than a promise
 * made by its callers.
 */
export function resetRequestAcceptedPage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].reset.accepted;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p><p style="color:${foxVar('text-muted')}; font-size:13px;">${html(t.hint)}</p>`,
		200,
		{ language }
	);
}

// The form the emailed link opens. Carries the token in a hidden field: retrieving this page consumes
// nothing, so a mail client or scanner that prefetches the link cannot burn it.
export function resetFormPage(
	token: string,
	context: SetPasswordContext,
	error?: string,
	language: Language = 'en'
): Response {
	const texts = PLAIN_TEXTS[language].reset;
	const invited = context.purpose === 'invite';
	const t = invited ? texts.inviteForm : texts.form;
	const values = { bucket: context.bucketName };
	const lead = invited
		? `<p style="color:${foxVar('text-secondary')};">${html(texts.inviteForm.lead)}</p>`
		: '';
	return page(
		text(t.title, values),
		`<h2 style="color:${foxVar('text')};">${html(t.title, values)}</h2>${lead}${errorHtml(error)}<form method="post" action="/reset-password"><input type="hidden" name="token" value="${esc(token)}"/><input name="password" type="password" autocomplete="new-password" placeholder="${html(t.password)}" required style="${input}"/><input name="confirmPassword" type="password" autocomplete="new-password" placeholder="${html(t.confirm)}" required style="${input}"/><button type="submit" style="${button}">${html(t.submit)}</button></form>`,
		// A re-render after a rejected submission is a failed request, and says so — the same rule
		// loginServer follows for its own error re-render.
		error ? 400 : 200,
		{ language }
	);
}

export function resetSuccessPage(
	purpose: SetPasswordPurpose,
	language: Language = 'en'
): Response {
	const texts = PLAIN_TEXTS[language].reset;
	const t = purpose === 'invite' ? texts.inviteSuccess : texts.success;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p>`,
		200,
		{ language }
	);
}

/*
 * One page for every refusal — unknown, expired, superseded, already used, mailed to an address the account no
 * longer holds, or an account that can no longer be reset. Saying which would tell a holder of one dead token
 * something about another. It cannot say whether the link was a reset or an invitation either: knowing that
 * takes a valid link, so it speaks for both.
 */
export function resetFailurePage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].reset.failure;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p><p style="color:${foxVar('text-muted')}; font-size:13px;">${html(t.hint)}</p>`,
		400,
		{ language }
	);
}
