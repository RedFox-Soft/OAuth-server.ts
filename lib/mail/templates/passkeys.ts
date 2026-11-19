// A person's own passkeys (specs/139): the link that proves the mailbox before an add or a removal, and the notices
// about both. The plain, inline-styled shape of the two-step mails, and their rule: a link is never inserted into a
// sentence. A notice names the project, the time, and the browser and system the passkey was made on — never the name
// the person gave it, its credential id, its public key or its AAGUID (specs/139 research R17).

import type { ActivityBrowser, ActivitySystem } from '../../adapters/types.js';
import { esc } from '../../html/escape.js';
import { formatDate, formatDateTime } from '../../i18n/format.js';
import type { Language } from '../../i18n/languages.js';
import { html, text } from '../../i18n/message.js';
import { ACCOUNT_TEXTS } from '../../i18n/texts/account/index.js';
import { EMAIL_TEXTS } from '../../i18n/texts/email/index.js';
import {
	BROWSER_NAMES,
	SYSTEM_NAMES
} from '../../person_activity/sign_in_words.js';
import type { RenderedEmail } from '../mailer.js';

export type PasskeyLink = 'passkey_add' | 'passkey_remove';

type Who = Readonly<{ service: string; email: string }>;

/* Where a passkey was made, from closed sets only. */
export interface MadeOn {
	browser: ActivityBrowser;
	system: ActivitySystem;
}

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

/*
 * "{browser} on {system}" in the reader's language, or null when both are unknown, in which case the clause is left
 * out of the sentence rather than saying "another browser on another system". Brand names stay as they are.
 */
export function deviceWords(made: MadeOn, language: Language): string | null {
	if (made.browser === 'other' && made.system === 'other') return null;
	const T = ACCOUNT_TEXTS[language];
	const browser = BROWSER_NAMES[made.browser] ?? T.otherBrowser;
	const system = SYSTEM_NAMES[made.system];
	return system === null ? browser : text(T.browserOn, { browser, system });
}

export function passkeyLinkEmail(
	purpose: PasskeyLink,
	who: Who,
	url: string,
	language: Language = 'en'
): RenderedEmail {
	const t = EMAIL_TEXTS[language].passkeys;
	const [subject, intro] =
		purpose === 'passkey_add'
			? [t.linkAddSubject, t.linkAddIntro]
			: [t.linkRemoveSubject, t.linkRemoveIntro];
	return {
		subject: text(subject, who),
		html: frame(language, [
			`<h2 style="font-size: 20px;">${html(t.linkHeading)}</h2>`,
			`<p>${html(intro, who)}</p>`,
			button(url, t.linkButton),
			`<p>${html(t.linkIgnore)}</p>`,
			bareLink(url, language)
		]),
		text: `${text(intro, who)}\n\n${url}\n\n${text(t.linkIgnore)}`,
		language
	};
}

export type PasskeyNotice =
	| { kind: 'added'; madeOn: MadeOn; at: number; disownUrl: string }
	| { kind: 'removed'; madeOn: MadeOn; createdAt: number }
	/* An administrator's revocation of one passkey, or of every one (specs/140): no link, and no name either. */
	| { kind: 'revoked'; madeOn: MadeOn; createdAt: number }
	| { kind: 'revoked_all'; count: number };

export function passkeyNoticeEmail(
	notice: PasskeyNotice,
	who: Who,
	language: Language = 'en'
): RenderedEmail {
	const t = EMAIL_TEXTS[language].passkeys;
	const device =
		notice.kind === 'revoked_all' ? null : deviceWords(notice.madeOn, language);
	// Written in UTC whatever the reader's zone, as the account pages write times, and said so where a time is shown.
	const values = {
		...who,
		...(notice.kind === 'revoked_all'
			? { count: String(notice.count) }
			: {
					date:
						notice.kind === 'added'
							? formatDateTime(language, notice.at)
							: formatDate(language, notice.createdAt)
				}),
		...(device === null ? {} : { device })
	};
	const parts: string[] = [];
	const lines: string[] = [];
	const say = (template: string) => {
		parts.push(`<p>${html(template, values)}</p>`);
		lines.push(text(template, values));
	};

	let subject: string;
	if (notice.kind === 'added') {
		subject = t.addedSubject;
		say(device === null ? t.addedIntroNoDevice : t.addedIntro);
		say(t.addedUse);
		say(t.disownLine);
		parts.push(
			button(notice.disownUrl, t.disownButton),
			bareLink(notice.disownUrl, language)
		);
		lines.push(notice.disownUrl);
	} else if (notice.kind === 'removed') {
		subject = t.removedSubject;
		say(device === null ? t.removedIntroNoDevice : t.removedIntro);
	} else {
		if (notice.kind === 'revoked') {
			subject = t.removedSubject;
			say(device === null ? t.revokedIntroNoDevice : t.revokedIntro);
		} else {
			subject = t.revokedAllSubject;
			say(t.revokedAllIntro);
		}
		say(t.signedOutEverywhere);
		say(t.revokedTell);
	}
	return {
		subject: text(subject, values),
		html: frame(language, parts),
		text: lines.join('\n\n'),
		language
	};
}
