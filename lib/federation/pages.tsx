// Every end-user-reachable failure of a federated sign-in, as a rendered page.
//
// All of them are terminal messages with no form and no next action inside the deployment, so all of them
// belong to the plain family — which is also what gives each a real status instead of a 200 wearing an
// apology (wiki/concepts/interaction-page-families.md). The one exception lives elsewhere: a user who
// declines at the provider comes back to the *login page* with an error, because that is a page they carry
// on working in.
//
// Nothing here builds HTML by hand. `page()` goes through htmlResponse, and test/csp/csp.spec.ts fails the
// suite if any other place constructs an HTML response. These pages reference no script, so they inherit
// `script-src 'none'`.

import { page } from '../interactions/plainPage.js';
import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import type { Language } from '../i18n/languages.js';
import { html, text } from '../i18n/message.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';

const heading = `color:${foxVar('text')};`;
const body = `color:${foxVar('text-secondary')};`;

// Every text here is a catalogue template without slots; the console-only pages pass English literals.
function terminal(
	title: string,
	message: string,
	status: number,
	link?: { href: string; label: string },
	language: Language = 'en'
): Response {
	const back = link
		? `<p style="margin-top:12px;"><a href="${esc(link.href)}" style="color:${foxVar('link')};">${html(link.label)}</a></p>`
		: '';
	return page(
		text(title),
		`<h2 style="${heading}">${html(title)}</h2><p style="${body}">${html(message)}</p>${back}`,
		status,
		{ language }
	);
}

/*
 * One message for every verification failure, and one for every unusable round trip.
 *
 * Which check failed is not something a caller gets to probe for by comparing responses — the specific
 * reason goes to the event bus instead. These two are separate pages only because their statuses differ in
 * what they tell a non-browser client, not because they say different things to a person.
 */
export function federationRejectedPage(
	uid?: string,
	language: Language = 'en'
): Response {
	const f = PLAIN_TEXTS[language].federation;
	const t = f.rejected;
	return terminal(
		t.title,
		t.body,
		400,
		uid ? { href: `/ui/${uid}/login`, label: f.backToSignIn } : undefined,
		language
	);
}

export function federationExpiredPage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].federation.expired;
	return terminal(t.title, t.body, 400, undefined, language);
}

/* The other side is broken, and saying so distinguishes it from "you are not allowed". */
export function federationUpstreamPage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].federation.upstream;
	return terminal(t.title, t.body, 502, undefined, language);
}

export function federationNoEmailPage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].federation.noEmail;
	return terminal(t.title, t.body, 400, undefined, language);
}

export function federationDomainRefusedPage(
	language: Language = 'en'
): Response {
	const t = PLAIN_TEXTS[language].federation.domainRefused;
	return terminal(t.title, t.body, 403, undefined, language);
}

/*
 * The one refusal with a usable next step, and the reason it exists: an untrusted or unverified assertion
 * must not silently take over an account that already holds the address.
 */
export function federationLinkRefusedPage(
	uid: string,
	language: Language = 'en'
): Response {
	const t = PLAIN_TEXTS[language].federation.linkRefused;
	return terminal(
		t.title,
		t.body,
		403,
		{ href: `/ui/${uid}/login`, label: t.link },
		language
	);
}

export function federationProvisioningClosedPage(
	language: Language = 'en'
): Response {
	const t = PLAIN_TEXTS[language].federation.provisioningClosed;
	return terminal(t.title, t.body, 403, undefined, language);
}

/* The console's own bucket: nobody here creates the account for you, an administrator invites you. */
export function federationNoConsoleAccountPage(): Response {
	return terminal(
		'You have no console account',
		'Signing in through this provider does not create a console account. Ask an administrator to invite you.',
		403
	);
}

export function federationInactivePage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].federation.inactive;
	return terminal(t.title, t.body, 403, undefined, language);
}

/*
 * Where a try of a provider ends (specs/088 R6): a plain page in the tab the provider sent back, never a
 * redirect into the console. The console's Strict session cookie would not survive the hop from the
 * provider's site, and a host-addressed bucket's callback is another origin anyway — the console tab that
 * started the try is already waiting for the result.
 */
export function tryFinishedPage(): Response {
	return terminal(
		'Try finished',
		'The result is in the console tab you started it from. You can close this tab and return to the console.',
		200
	);
}

/* The try record ran out (ten minutes) before the provider answered; nobody is left to read a result. */
export function tryExpiredPage(): Response {
	return terminal(
		'This try is no longer valid',
		'The try took too long to complete. Start it again from the console.',
		400
	);
}

/* `passwordLogin: false` — the password-only doors of a federated-only bucket. */
export function passwordLoginClosedPage(
	uid?: string,
	language: Language = 'en'
): Response {
	const f = PLAIN_TEXTS[language].federation;
	const t = f.passwordLoginClosed;
	return terminal(
		t.title,
		t.body,
		403,
		uid ? { href: `/ui/${uid}/login`, label: f.backToSignIn } : undefined,
		language
	);
}
