// An administrator's invitation for a person to set their own password (specs/089). Same plain, inline-styled,
// table-free shape as the reset template, because it has to render in a mail client, not a browser.
//
// Distinct from the reset message on purpose: the person did not ask for anything, so a message saying "we
// received a request to reset your password" would read as somebody else's request — the confusion inviting
// people through "forgot password" caused. It names the bucket, says what the link does and how long it works,
// and carries no password, no account id and no bucket id: forwarded, it hands over the link and nothing else.

import { esc } from '../../html/escape.js';
import type { Language } from '../../i18n/languages.js';
import { html, text } from '../../i18n/message.js';
import { EMAIL_TEXTS } from '../../i18n/texts/email/index.js';
import type { RenderedEmail } from '../mailer.js';

interface UserInvitationParams {
	bucketName: string;
	url: string;
}

export function userInvitationEmail(
	params: UserInvitationParams,
	language: Language = 'en'
): RenderedEmail {
	const { bucketName, url } = params;
	const texts = EMAIL_TEXTS[language];
	const t = texts.invitation;
	const body = [
		`<div lang="${language}" style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">${html(t.heading, { bucket: bucketName })}</h2>`,
		`<p>${html(t.intro, { bucket: bucketName })}</p>`,
		`<p style="text-align: center; margin: 28px 0;">`,
		`<a href="${esc(url)}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">${html(t.button)}</a>`,
		`</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">${html(texts.pasteLink)}<br/>${html('{url}', { url })}</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">${html(t.expiry)}</p>`,
		`<p style="color: #8c8c8c; font-size: 12px; margin-top: 24px;">${html(t.ignore)}</p>`,
		`</div>`
	].join('');
	return {
		subject: text(t.subject, { bucket: bucketName }),
		html: body,
		text: text(t.text, { bucket: bucketName, url }),
		language
	};
}
