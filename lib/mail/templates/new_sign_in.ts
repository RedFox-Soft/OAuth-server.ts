// A sign-in from a new network or browser (specs/138 contracts/email-and-pages.md). Same plain, inline-styled shape as
// the other end-user mails. One fact a line, each a value from a fixed table or a looked-up name, never the request's
// own text; never the network address. The "This wasn't me" link is never inside a sentence.

import { esc } from '../../html/escape.js';
import { formatDateTime } from '../../i18n/format.js';
import type { Language } from '../../i18n/languages.js';
import { html, text } from '../../i18n/message.js';
import { EMAIL_TEXTS } from '../../i18n/texts/email/index.js';
import type { Newness } from '../../sign_in_alerts/judge.js';
import type { RenderedEmail } from '../mailer.js';

export interface NewSignInFacts {
	/* The name the project shows its people (`shownNameOf`), or null for the administrators' project, the FoxAuth console. */
	service: string | null;
	email: string;
	at: Date;
	app: string;
	method: string;
	browser: string | null;
	place: string | null;
	network: string | null;
	why: Newness;
}

export function newSignInEmail(
	facts: NewSignInFacts,
	url: string,
	language: Language
): RenderedEmail {
	const t = EMAIL_TEXTS[language].newSignIn;
	const service = facts.service ?? t.console;
	const lines: [string, Record<string, string>][] = [
		[t.when, { when: formatDateTime(language, facts.at.getTime()) }],
		[t.app, { app: facts.app }],
		[t.method, { method: facts.method }],
		...(facts.browser === null
			? []
			: [
					[t.browser, { browser: facts.browser }] as [
						string,
						Record<string, string>
					]
				]),
		...(facts.place === null
			? []
			: [
					[t.place, { place: facts.place }] as [string, Record<string, string>]
				]),
		...(facts.network === null
			? []
			: [
					[t.network, { network: facts.network }] as [
						string,
						Record<string, string>
					]
				])
	];
	const why =
		facts.why === 'both'
			? t.whyBoth
			: facts.why === 'network'
				? t.whyNetwork
				: t.whyBrowser;
	const who = { service, email: facts.email };
	return {
		subject: text(t.subject, who),
		html: [
			`<div lang="${language}" style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
			`<h2 style="font-size: 20px;">${html(t.heading)}</h2>`,
			`<p>${html(t.intro, who)}</p>`,
			`<p>${lines.map(([line, values]) => html(line, values)).join('<br/>')}</p>`,
			`<p>${html(why)}</p>`,
			`<p>${html(t.ifYou)}</p>`,
			`<p>${html(t.ifNot)}</p>`,
			`<p style="text-align: center; margin: 28px 0;"><a href="${esc(url)}" style="background: #cf1322; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">${html(t.button)}</a></p>`,
			`<p style="font-size: 12px; color: #8c8c8c;">${html(EMAIL_TEXTS[language].pasteLink)}<br/>${html('{url}', { url })}</p>`,
			`</div>`
		].join(''),
		text: [
			text(t.intro, who),
			'',
			...lines.map(([line, values]) => text(line, values)),
			'',
			text(why),
			text(t.ifYou),
			text(t.ifNot),
			url
		].join('\n'),
		language
	};
}
