// About a person's account at a connected service (specs/118 R12): it broke, an administrator disconnected it, or
// its service was deleted. Same plain, inline-styled, table-free shape as the invitation template, because it has
// to render in a mail client. Names the service, the account's label and the project, and links to the person's
// connected accounts; carries no token and no identifier.

import { esc } from '../../html/escape.js';
import type { Language } from '../../i18n/languages.js';
import { html, text } from '../../i18n/message.js';
import { EMAIL_TEXTS } from '../../i18n/texts/email/index.js';
import type { RenderedEmail } from '../mailer.js';

export type ConnectedAccountNotice = 'broken' | 'removed' | 'service_removed';

interface NoticeParams {
	bucketName: string;
	serviceName: string;
	label: string;
	url: string;
}

export function connectedAccountEmail(
	notice: ConnectedAccountNotice,
	params: NoticeParams,
	language: Language = 'en'
): RenderedEmail {
	const texts = EMAIL_TEXTS[language];
	const t = texts.connectedAccount;
	const values = {
		bucket: params.bucketName,
		service: params.serviceName,
		label: params.label
	};
	const [subject, heading, intro] =
		notice === 'broken'
			? [t.brokenSubject, t.brokenHeading, t.brokenIntro]
			: [
					t.removedSubject,
					t.removedHeading,
					notice === 'removed' ? t.removedIntro : t.serviceRemovedIntro
				];
	const body = [
		`<div lang="${language}" style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">${html(heading, values)}</h2>`,
		`<p>${html(intro, values)}</p>`,
		`<p style="text-align: center; margin: 28px 0;">`,
		`<a href="${esc(params.url)}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">${html(t.button)}</a>`,
		`</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">${html(texts.pasteLink)}<br/>${html('{url}', { url: params.url })}</p>`,
		`</div>`
	].join('');
	return {
		subject: text(subject, values),
		html: body,
		text: `${text(intro, values)}\n\n${params.url}`,
		language
	};
}
