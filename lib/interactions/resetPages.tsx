// Standalone server-rendered pages for the self-service password reset. Three of the four screens are
// reached from a link in an email (often a different browser, always without the interaction cookie), so
// the whole family is plain, self-contained HTML with no dependency on the OIDC interaction cookie or the
// antd shell — the same reasoning verifyPages.tsx records, and the reason the request form joins them
// rather than matching the login page it is reached from.

import { page } from './plainPage.js';
import { esc } from '../html/escape.js';
import type { SetPasswordPurpose } from '../password_reset/types.js';

/*
 * What the page knows about the link it was opened from (specs/089). A reset and an administrator's invitation
 * share the secret and the form; only the words differ, and only once the link has been found valid — an
 * invalid link has no purpose to show, which is why the failure page below speaks for both.
 */
export interface SetPasswordContext {
	purpose: SetPasswordPurpose;
	bucketName: string;
}

const input =
	'width:100%; box-sizing:border-box; padding:10px; margin-bottom:12px; border:1px solid #d9d9d9; border-radius:6px;';
const button =
	'background:#1677ff; color:#fff; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; width:100%;';

function errorHtml(error?: string): string {
	return error ? `<p style="color:#cf1322;">${esc(error)}</p>` : '';
}

// Where a locked-out user starts. Inside the interaction (the form posts back to `ui/:uid`), because the
// bucket an address is looked up in has to come from the client that began the authorization request.
export function resetRequestPage(uid: string, error?: string): Response {
	return page(
		'Reset your password',
		`<h2 style="color:#1f1f1f;">Reset your password</h2><p style="color:#595959;">Enter the email address for your account and we will send you a link to choose a new password.</p>${errorHtml(error)}<form method="post" action="/ui/${esc(uid)}/forgot-password"><input name="email" type="email" autocomplete="email" placeholder="you@example.com" required style="${input}"/><button type="submit" style="${button}">Send reset link</button></form><p style="margin-top:12px;"><a href="/ui/${esc(uid)}/login" style="color:#1677ff;">Back to sign in</a></p>`
	);
}

/*
 * The one answer every request gets: registered, unregistered, another bucket's address, a deactivated
 * account, the reserved admin bucket, a send that failed, or one the cooldown or daily cap held back —
 * that last because the throttle exists only for addresses with an account. A constant with nothing
 * interpolated, so "byte-identical across outcomes" is a property of this function rather than a promise
 * made by its callers.
 */
export function resetRequestAcceptedPage(): Response {
	return page(
		'Check your email',
		`<h2 style="color:#1f1f1f;">Check your email</h2><p style="color:#595959;">If that address has an account, a password reset link is on its way. The link expires in one hour.</p><p style="color:#8c8c8c; font-size:13px;">Not seeing it? Check your spam folder first. A new link is sent at most once a minute and a few times a day, so a request made sooner than that sends nothing.</p>`
	);
}

// The form the emailed link opens. Carries the token in a hidden field: retrieving this page consumes
// nothing, so a mail client or scanner that prefetches the link cannot burn it.
export function resetFormPage(
	token: string,
	context: SetPasswordContext,
	error?: string
): Response {
	const invited = context.purpose === 'invite';
	const title = invited
		? `Set your password for ${context.bucketName}`
		: 'Choose a new password';
	const lead = invited
		? `<p style="color:#595959;">Choose the password you will sign in with. Setting it also confirms your email address.</p>`
		: '';
	return page(
		title,
		`<h2 style="color:#1f1f1f;">${esc(title)}</h2>${lead}${errorHtml(error)}<form method="post" action="/reset-password"><input type="hidden" name="token" value="${esc(token)}"/><input name="password" type="password" autocomplete="new-password" placeholder="${invited ? 'Password' : 'New password'}" required style="${input}"/><input name="confirmPassword" type="password" autocomplete="new-password" placeholder="${invited ? 'Repeat password' : 'Repeat new password'}" required style="${input}"/><button type="submit" style="${button}">${invited ? 'Set password' : 'Set new password'}</button></form>`,
		// A re-render after a rejected submission is a failed request, and says so — the same rule
		// loginServer follows for its own error re-render.
		error ? 400 : 200
	);
}

export function resetSuccessPage(purpose: SetPasswordPurpose): Response {
	if (purpose === 'invite') {
		return page(
			'Password set',
			`<h2 style="color:#1f1f1f;">Your password is set</h2><p style="color:#595959;">You can sign in now. Return to the application and sign in with your email address and the password you just chose.</p>`
		);
	}
	return page(
		'Password updated',
		`<h2 style="color:#1f1f1f;">Password updated</h2><p style="color:#595959;">Your password has been changed and you have been signed out everywhere. Return to the application to sign in.</p>`
	);
}

/*
 * One page for every refusal — unknown, expired, superseded, already used, mailed to an address the account no
 * longer holds, or an account that can no longer be reset. Saying which would tell a holder of one dead token
 * something about another. It cannot say whether the link was a reset or an invitation either: knowing that
 * takes a valid link, so it speaks for both.
 */
export function resetFailurePage(): Response {
	return page(
		'Link invalid',
		`<h2 style="color:#1f1f1f;">This link is no longer valid</h2><p style="color:#595959;">Reset links expire after an hour and invitation links after 7 days; a newer one replaces an older one, and each works once.</p><p style="color:#8c8c8c; font-size:13px;">Request a new reset link from the application's sign-in page, or ask whoever invited you to send another invitation.</p>`,
		400
	);
}
