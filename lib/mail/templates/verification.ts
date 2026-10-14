// Standard verification email. Deliberately plain, inline-styled, table-free HTML with a
// plaintext fallback so it renders across mail clients (the antd/React interaction pages
// are for browsers, not inboxes).

import { esc } from '../../html/escape.js';
import type { Language } from '../../i18n/languages.js';
import { html, text } from '../../i18n/message.js';
import { EMAIL_TEXTS } from '../../i18n/texts/email/index.js';
import type { RenderedEmail } from '../mailer.js';

interface LinkParams {
	appName: string;
	verifyUrl: string;
}

interface CodeParams {
	appName: string;
	code: string;
}

function shell(language: Language, appName: string, bodyHtml: string): string {
	const t = EMAIL_TEXTS[language].verification;
	return [
		`<div lang="${language}" style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">${html(t.heading)}</h2>`,
		`<p>${html(t.intro, { app: appName })}</p>`,
		bodyHtml,
		`<p style="color: #8c8c8c; font-size: 12px; margin-top: 24px;">${html(t.ignore)}</p>`,
		`</div>`
	].join('');
}

export function verificationLinkEmail(
	params: LinkParams,
	language: Language = 'en'
): RenderedEmail {
	const { appName, verifyUrl } = params;
	const texts = EMAIL_TEXTS[language];
	const t = texts.verification.link;
	const body = shell(
		language,
		appName,
		[
			`<p style="text-align: center; margin: 28px 0;">`,
			`<a href="${esc(verifyUrl)}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">${html(t.button)}</a>`,
			`</p>`,
			`<p style="font-size: 12px; color: #8c8c8c;">${html(texts.pasteLink)}<br/>${html('{url}', { url: verifyUrl })}</p>`
		].join('')
	);
	return {
		subject: text(t.subject, { app: appName }),
		html: body,
		text: text(t.text, { app: appName, url: verifyUrl }),
		language
	};
}

export function verificationCodeEmail(
	params: CodeParams,
	language: Language = 'en'
): RenderedEmail {
	const { appName, code } = params;
	const t = EMAIL_TEXTS[language].verification.code;
	const body = shell(
		language,
		appName,
		[
			`<p>${html(t.prompt)}</p>`,
			`<p style="text-align: center; margin: 24px 0;">`,
			`<span style="font-size: 32px; letter-spacing: 8px; font-weight: bold;">${html('{code}', { code })}</span>`,
			`</p>`,
			`<p style="font-size: 12px; color: #8c8c8c;">${html(t.expiry)}</p>`
		].join('')
	);
	return {
		subject: text(t.subject, { app: appName }),
		html: body,
		text: text(t.text, { app: appName, code }),
		language
	};
}
