// Standard password-reset email. Deliberately plain, inline-styled, table-free HTML with a plaintext
// fallback so it renders across mail clients (the antd/React interaction pages are for browsers, not
// inboxes) — the same shape templates/verification.ts uses.
//
// Carries the link and nothing else about the account: no password, no hash, no account id, no bucket id.
// A forwarded reset email should hand the recipient the ability to set a password and no other knowledge.

import { esc } from '../../html/escape.js';
import type { Language } from '../../i18n/languages.js';
import { html, text } from '../../i18n/message.js';
import { EMAIL_TEXTS } from '../../i18n/texts/email/index.js';
import type { RenderedEmail } from '../mailer.js';

interface ResetParams {
	appName: string;
	resetUrl: string;
}

export function passwordResetEmail(
	params: ResetParams,
	language: Language = 'en'
): RenderedEmail {
	const { appName, resetUrl } = params;
	const texts = EMAIL_TEXTS[language];
	const t = texts.passwordReset;
	const body = [
		`<div lang="${language}" style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">${html(t.heading)}</h2>`,
		`<p>${html(t.intro, { app: appName })}</p>`,
		`<p style="text-align: center; margin: 28px 0;">`,
		`<a href="${esc(resetUrl)}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">${html(t.button)}</a>`,
		`</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">${html(texts.pasteLink)}<br/>${html('{url}', { url: resetUrl })}</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">${html(t.expiry)}</p>`,
		`<p style="color: #8c8c8c; font-size: 12px; margin-top: 24px;">${html(t.ignore)}</p>`,
		`</div>`
	].join('');
	return {
		subject: text(t.subject, { app: appName }),
		html: body,
		text: text(t.text, { app: appName, url: resetUrl }),
		language
	};
}
