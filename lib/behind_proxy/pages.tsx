/*
 * The pages a proxy shows in an app's place (specs/122 R15). Plain family: they are reached on the app's host, with
 * no interaction cookie and no bundle, and each is a terminal message with one link
 * (wiki/concepts/interaction-page-families.md). A refusal answers 403, never 200, because a proxy and any client
 * that is not a browser read only the status.
 */

import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import { formatDateTime } from '../i18n/format.js';
import type { Language } from '../i18n/languages.js';
import { html, text } from '../i18n/message.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';
import { page } from '../interactions/plainPage.js';

const heading = `color:${foxVar('text')};`;
const body = `color:${foxVar('text-secondary')};`;
const small = `color:${foxVar('text-secondary')}; font-size:12px; margin-top:16px;`;

function link(href: string, label: string): string {
	return `<p style="margin-top:12px;"><a href="${esc(href)}" style="color:${foxVar('link')};">${html(label)}</a></p>`;
}

function reasonLine(
	template: string,
	reason: string,
	language: Language
): string {
	return `<p style="${small}">${html(template, {
		reason,
		time: formatDateTime(language, Date.now())
	})}</p>`;
}

/* A signed-in person the rules turn away: who they are signed in as, and a way to be someone else. */
export function deniedPage(input: {
	host: string;
	email: string;
	reason: string;
	/* The app's sign-out, which then starts a new sign-in. */
	otherAccountHref: string;
	language: Language;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.denied;
	return page(
		text(t.title, { host: input.host }),
		`<h2 style="${heading}">${html(t.title, { host: input.host })}</h2>` +
			`<p style="${body}">${html(t.signedInAs, { email: input.email })}</p>` +
			link(input.otherAccountHref, t.otherAccount) +
			reasonLine(t.reason, input.reason, input.language),
		403,
		{ language: input.language }
	);
}

/* A sign-in that came back unusable: no session was made, and starting again is the only next step. */
export function signInFailedPage(input: {
	host: string;
	reason: string;
	startHref: string;
	language: Language;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.signInFailed;
	return page(
		text(t.title, { host: input.host }),
		`<h2 style="${heading}">${html(t.title, { host: input.host })}</h2>` +
			`<p style="${body}">${html(t.body)}</p>` +
			link(input.startHref, t.tryAgain) +
			reasonLine(t.reason, input.reason, input.language),
		403,
		{ language: input.language }
	);
}
