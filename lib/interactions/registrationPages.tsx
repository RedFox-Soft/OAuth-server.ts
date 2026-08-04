/*
 * The two terminal registration refusals. They belong to the plain family rather than the antd shell
 * because neither has a form: there is nothing for the user to work in and nothing to hydrate, so a
 * client bundle and an inline props script would be payload for a page that only carries a sentence.
 *
 * The re-render after a password mismatch is deliberately *not* here — that one is the user's own form
 * coming back with their address still in it, which only the hydrated family can do.
 */

import { page } from './plainPage.js';

// Constants with nothing interpolated: the same refusal reaches the GET and the POST, and "identical
// whichever way you got here" is then a property of the function rather than a promise at two call sites.
export function registrationClosedPage(): Response {
	return page(
		'Registration closed',
		`<h2 style="color:#1f1f1f;">Not accepting new accounts</h2><p style="color:#595959;">This application is not accepting new accounts at the moment.</p><p style="color:#8c8c8c; font-size:13px;">If you already have an account, return to the application and sign in.</p>`,
		403
	);
}

/*
 * The account exists and is unverified by the time this renders, so the wording must neither claim the
 * sign-up failed nor invite the same address to register again — it is taken, by them.
 */
export function registrationSendFailedPage(): Response {
	return page(
		'Verification email not sent',
		`<h2 style="color:#1f1f1f;">We could not send your verification email</h2><p style="color:#595959;">Your account was created, but the verification message could not be sent. Return to the application and sign in to have another one sent.</p>`,
		502
	);
}
