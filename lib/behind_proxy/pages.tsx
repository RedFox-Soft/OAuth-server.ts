/*
 * The pages a proxy shows in an app's place (specs/122 R15). Plain family: they are reached on the app's host, with
 * no interaction cookie and no bundle, and each is a terminal message with one link
 * (wiki/concepts/interaction-page-families.md). A refusal answers 403, never 200, because a proxy and any client
 * that is not a browser read only the status.
 */

import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import {
	formatDateTimeIn,
	formatIn,
	formatWeekdayTime
} from '../i18n/format.js';
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

/* The reason code and the moment, in the app's own time zone when it has one (specs/124 FR-028). */
function reasonLine(
	template: string,
	reason: string,
	language: Language,
	zone: string | null = null
): string {
	const time = formatDateTimeIn(language, Date.now(), zone);
	return `<p style="${small}">${html(template, {
		reason,
		time: zone ? `${time} ${zone}` : time
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
	/* The app's own time zone, when it has one (specs/124 FR-028). */
	zone?: string | null;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.denied;
	return page(
		text(t.title, { host: input.host }),
		`<h2 style="${heading}">${html(t.title, { host: input.host })}</h2>` +
			`<p style="${body}">${html(t.signedInAs, { email: input.email })}</p>` +
			link(input.otherAccountHref, t.otherAccount) +
			reasonLine(t.reason, input.reason, input.language, input.zone ?? null),
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

/*
 * Refused for the network the person is on (specs/124 FR-028): asked before any sign-in, so the page names no one and
 * offers no other account — another account from the same network would be refused the same way. Which range failed
 * is not said: a list of the networks that are let in is not the visitor's to read.
 */
export function networkDeniedPage(input: {
	host: string;
	reason: string;
	language: Language;
	zone: string | null;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.network;
	return page(
		text(t.title, { host: input.host }),
		`<h2 style="${heading}">${html(t.title, { host: input.host })}</h2>` +
			`<p style="${body}">${html(t.body)}</p>` +
			reasonLine(t.reason, input.reason, input.language, input.zone),
		403,
		{ language: input.language }
	);
}

/* Refused for the hour: when the app opens again, in its own zone, and how far off that is. */
export function closedPage(input: {
	host: string;
	reason: string;
	language: Language;
	zone: string | null;
	opening: { day: number; minute: number; inMinutes: number } | null;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.closed;
	const when = input.opening
		? html(t.opens, {
				when: formatWeekdayTime(
					input.language,
					input.opening.day,
					input.opening.minute
				),
				zone: input.zone ?? 'UTC',
				inTime: formatIn(input.language, input.opening.inMinutes)
			})
		: html(t.never);
	return page(
		text(t.title, { host: input.host }),
		`<h2 style="${heading}">${html(t.title, { host: input.host })}</h2>` +
			`<p style="${body}">${when}</p>` +
			reasonLine(t.reason, input.reason, input.language, input.zone),
		403,
		{ language: input.language }
	);
}

/* A fresh sign-in that came back older than the page asks for: try again, never a loop of redirects. */
export function notConfirmedPage(input: {
	host: string;
	reason: string;
	startHref: string;
	language: Language;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.notConfirmed;
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

/*
 * A page that asks for a sign-in with a code from an authenticator app, reached without one (specs/128 research R6):
 * the person went back from the refusal page, or the sign-in came back without a code. It never starts the same
 * sign-in again; the one link opens the app's start page, and only when that page asks for no code itself.
 */
export function codeNeededPage(input: {
	host: string;
	openHref?: string;
	language: Language;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.codeNeeded;
	return page(
		text(t.title, { host: input.host }),
		`<h2 style="${heading}">${html(t.title, { host: input.host })}</h2>` +
			`<p style="${body}">${html(t.body, { host: input.host })}</p>` +
			(input.openHref
				? `<p style="margin-top:12px;"><a href="${esc(input.openHref)}" style="color:${foxVar('link')};">${html(t.open, { host: input.host })}</a></p>`
				: '') +
			reasonLine(t.reason, 'code_required', input.language),
		403,
		{ language: input.language }
	);
}

export type AddressCause = 'noKey' | 'wrongKey' | 'several' | 'notPublic';

/*
 * The proxy self-test (specs/124 research R6): the requester's own address as the check believed it, or why it
 * believed none. Shown to the one person whose address it is, and stored nowhere. Answered 403, never 2xx: a proxy
 * reads any success of its check as "let the request through to the app", and would never show this page.
 */
export function addressPage(input: {
	host: string;
	address: string | null;
	cause: AddressCause | null;
	reported: string | null;
	language: Language;
}): Response {
	const t = PLAIN_TEXTS[input.language].behindProxy.address;
	const causes: Record<AddressCause, string> = {
		noKey: t.causeNoKey,
		wrongKey: t.causeWrongKey,
		several: t.causeSeveral,
		notPublic: t.causeNotPublic
	};
	const line =
		input.address !== null
			? html(t.seen, { address: input.address })
			: html(t.unknown, {
					cause: text(causes[input.cause ?? 'several'], {
						address: input.reported ?? ''
					})
				});
	return page(
		text(t.title, { host: input.host }),
		`<h2 style="${heading}">${html(t.title, { host: input.host })}</h2>` +
			`<p style="${body}">${line}</p>`,
		403,
		{ language: input.language }
	);
}
