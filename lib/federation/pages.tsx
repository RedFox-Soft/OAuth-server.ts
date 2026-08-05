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

import { esc, page } from '../interactions/plainPage.js';

const heading = 'color:#1f1f1f;';
const body = 'color:#595959;';

function terminal(
	title: string,
	message: string,
	status: number,
	link?: { href: string; label: string }
): Response {
	const back = link
		? `<p style="margin-top:12px;"><a href="${esc(link.href)}" style="color:#1677ff;">${esc(link.label)}</a></p>`
		: '';
	return page(
		title,
		`<h2 style="${heading}">${esc(title)}</h2><p style="${body}">${esc(message)}</p>${back}`,
		status
	);
}

/*
 * One message for every verification failure, and one for every unusable round trip.
 *
 * Which check failed is not something a caller gets to probe for by comparing responses — the specific
 * reason goes to the event bus instead. These two are separate pages only because their statuses differ in
 * what they tell a non-browser client, not because they say different things to a person.
 */
export function federationRejectedPage(uid?: string): Response {
	return terminal(
		'Sign-in could not be completed',
		'We could not verify the response from your identity provider. Please start again.',
		400,
		uid ? { href: `/ui/${uid}/login`, label: 'Back to sign in' } : undefined
	);
}

export function federationExpiredPage(): Response {
	return terminal(
		'This sign-in is no longer valid',
		'The sign-in took too long, or this link has already been used. Please start again from the application.',
		400
	);
}

/* The other side is broken, and saying so distinguishes it from "you are not allowed". */
export function federationUpstreamPage(): Response {
	return terminal(
		'Your identity provider could not be reached',
		'We could not complete the exchange with your identity provider. This is usually temporary — please try again shortly.',
		502
	);
}

export function federationNoEmailPage(): Response {
	return terminal(
		'Your identity provider sent no email address',
		'We need an email address to sign you in, and your identity provider did not supply one. Ask your administrator to release your address to this application.',
		400
	);
}

export function federationDomainRefusedPage(): Response {
	return terminal(
		'This account cannot use this application',
		'Your email address is not in a domain this application accepts.',
		403
	);
}

/*
 * The one refusal with a usable next step, and the reason it exists: an untrusted or unverified assertion
 * must not silently take over an account that already holds the address.
 */
export function federationLinkRefusedPage(uid: string): Response {
	return terminal(
		'An account already exists for this address',
		'An account with this email address already exists here. Sign in with your password instead.',
		403,
		{ href: `/ui/${uid}/login`, label: 'Sign in with your password' }
	);
}

export function federationProvisioningClosedPage(): Response {
	return terminal(
		'No account here yet',
		'This application does not create accounts automatically. Ask your administrator to create one for you first.',
		403
	);
}

export function federationInactivePage(): Response {
	return terminal(
		'This account is not active',
		'Your account has been deactivated. Please contact your administrator.',
		403
	);
}

/* `passwordLogin: false` — the password-only doors of a federated-only bucket. */
export function passwordLoginClosedPage(uid?: string): Response {
	return terminal(
		'Password sign-in is not available',
		'This application signs you in through your identity provider. There is no password to enter, reset, or register here.',
		403,
		uid ? { href: `/ui/${uid}/login`, label: 'Back to sign in' } : undefined
	);
}
