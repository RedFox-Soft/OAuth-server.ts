// A person's own two-step verification (specs/126): the link that proves the mailbox, and the notices about every
// change to their factor. Same plain, inline-styled, table-free shape as the other end-user mails, because it has to
// render in a mail client. A link is never inserted into a sentence: a sentence, then the link on its own.

import { esc } from '../../html/escape.js';
import { formatDateTime } from '../../i18n/format.js';
import type { Language } from '../../i18n/languages.js';
import { html, text } from '../../i18n/message.js';
import { EMAIL_TEXTS } from '../../i18n/texts/email/index.js';
import { SIGN_IN_TEXTS } from '../../i18n/texts/signIn/index.js';
import type { RenderedEmail } from '../mailer.js';

export type TwoStepLink = 'enrol' | 'replace' | 'reenrol';

export type TwoStepNotice =
	| { kind: 'on'; disownUrl: string }
	| { kind: 'changed'; disownUrl: string }
	| { kind: 'off'; pageUrl: string }
	| { kind: 'removed'; pageUrl?: string; required?: boolean }
	| { kind: 'guess' };

type Who = Readonly<{ service: string; email: string }> &
	Readonly<Record<string, string>>;

function frame(language: Language, parts: string[]): string {
	return [
		`<div lang="${language}" style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		...parts,
		`</div>`
	].join('');
}

function button(url: string, label: string): string {
	return `<p style="text-align: center; margin: 28px 0;"><a href="${esc(url)}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">${html(label)}</a></p>`;
}

function bareLink(url: string, language: Language): string {
	return `<p style="font-size: 12px; color: #8c8c8c;">${html(EMAIL_TEXTS[language].pasteLink)}<br/>${html('{url}', { url })}</p>`;
}

export function twoStepLinkEmail(
	purpose: TwoStepLink,
	who: Who,
	url: string,
	language: Language = 'en'
): RenderedEmail {
	const t = EMAIL_TEXTS[language].twoStep;
	const [subject, intro] =
		purpose === 'enrol'
			? [t.linkEnrolSubject, t.linkEnrolIntro]
			: purpose === 'replace'
				? [t.linkReplaceSubject, t.linkReplaceIntro]
				: [t.linkReenrolSubject, t.linkReenrolIntro];
	return {
		subject: text(subject, who),
		html: frame(language, [
			`<h2 style="font-size: 20px;">${html(t.linkHeading)}</h2>`,
			`<p>${html(intro, who)}</p>`,
			button(url, t.linkButton),
			`<p>${html(t.linkWarning)}</p>`,
			bareLink(url, language)
		]),
		text: `${text(intro, who)}\n\n${url}\n\n${text(t.linkWarning)}`,
		language
	};
}

export function twoStepNoticeEmail(
	notice: TwoStepNotice,
	who: Who,
	language: Language = 'en',
	at: number = Date.now()
): RenderedEmail {
	const t = EMAIL_TEXTS[language].twoStep;
	// Written in UTC whatever the reader's zone, as the account pages write times, and said so.
	const values = { ...who, date: `${formatDateTime(language, at)} UTC` };
	const parts: string[] = [];
	const lines: string[] = [];
	const say = (template: string) => {
		parts.push(`<p>${html(template, values)}</p>`);
		lines.push(text(template, values));
	};
	const link = (url: string, label: string) => {
		parts.push(button(url, label), bareLink(url, language));
		lines.push(url);
	};

	let subject: string;
	switch (notice.kind) {
		case 'on':
		case 'changed':
			subject = notice.kind === 'on' ? t.onSubject : t.changedSubject;
			say(notice.kind === 'on' ? t.onIntro : t.changedIntro);
			say(t.disownLine);
			link(notice.disownUrl, t.disownButton);
			break;
		case 'off':
			subject = t.offSubject;
			say(t.offIntro);
			say(t.offWarning);
			link(notice.pageUrl, t.pageButton);
			break;
		case 'removed':
			subject = t.removedSubject;
			say(t.removedIntro);
			if (notice.required) {
				say(t.removedAgainRequired);
			} else if (notice.pageUrl) {
				say(t.removedAgainSelf);
				link(notice.pageUrl, t.pageButton);
			}
			say(t.removedWarning);
			break;
		case 'guess': {
			subject = t.guessSubject;
			say(t.guessIntro);
			const advice = {
				...values,
				forgot: SIGN_IN_TEXTS[language].login.forgotPassword
			};
			parts.push(`<p>${html(t.guessAdvice, advice)}</p>`);
			lines.push(text(t.guessAdvice, advice));
			break;
		}
	}
	return {
		subject: text(subject, values),
		html: frame(language, parts),
		text: lines.join('\n\n'),
		language
	};
}
